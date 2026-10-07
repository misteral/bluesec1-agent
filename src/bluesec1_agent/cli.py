import argparse
import asyncio
import json
import signal
import sys

import truststore
from pydantic import ValidationError

from bluesec1_agent.agent import SYSTEM_PROMPTS, SimpleSGRAgent
from bluesec1_agent.jev_agent import JevNavigatorAgent
from bluesec1_agent.jev_client import JevClient
from bluesec1_agent.llm import OpenAIStructuredStepClient
from bluesec1_agent.settings import Settings
from bluesec1_agent.tracking import RunRecorder, git_state, sha256_text
from bluesec1_client import (
    CompetitionClosedError,
    RemoteAuthenticationError,
    RemoteBenchmarkClient,
    RemoteRateLimitError,
    RemoteUnavailableError,
    RunCapacityExceededError,
)


def build_parser() -> argparse.ArgumentParser:
    """Build the remote-runtime command-line interface.

    Returns:
        Configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description="Run the structured-generation agent against scenario-runtime."
    )
    parser.add_argument("--endpoint", help="Override SCENARIO_RUNTIME_ENDPOINT.")
    parser.add_argument("--token", help="Override SCENARIO_RUNTIME_TOKEN.")
    parser.add_argument("--run-label", help="Override REMOTE_RUN_LABEL.")
    parser.add_argument("--agent-name", help="Override AGENT_NAME.")
    parser.add_argument("--arena", help="Override SCENARIO_RUNTIME_ARENA.")
    parser.add_argument(
        "--experiment",
        default="adhoc",
        help="Experiment id used in the runs/ directory name, e.g. exp-002-compact-context.",
    )
    parser.add_argument(
        "--no-record",
        action="store_true",
        help="Do not write run artifacts under runs/.",
    )
    parser.add_argument(
        "--verify-tls",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Override SCENARIO_RUNTIME_VERIFY_TLS.",
    )
    return parser


async def run(args: argparse.Namespace) -> None:
    """Execute one new remote run and print its task results.

    Args:
        args: Parsed command-line arguments.
    """
    truststore.inject_into_ssl()
    settings = _load_settings()
    llm = OpenAIStructuredStepClient(
        base_url=settings.llm_base_url,
        api_key=settings.llm_api_key.get_secret_value(),
        model=settings.llm_default_model,
        timeout_seconds=settings.llm_timeout_seconds,
        max_completion_tokens=settings.llm_max_completion_tokens,
        max_retries=settings.llm_max_step_retries,
        response_format=settings.llm_response_format,
    )
    review_llm = None
    if settings.llm_review_model:
        review_llm = OpenAIStructuredStepClient(
            base_url=settings.llm_base_url,
            api_key=settings.llm_api_key.get_secret_value(),
            model=settings.llm_review_model,
            timeout_seconds=settings.llm_timeout_seconds,
            max_completion_tokens=settings.llm_max_completion_tokens,
            max_retries=settings.llm_max_step_retries,
            response_format=settings.llm_response_format,
        )
    agent_name = args.agent_name or settings.agent_name
    verify_tls = (
        settings.scenario_runtime_verify_tls if args.verify_tls is None else args.verify_tls
    )
    arena = args.arena or settings.scenario_runtime_arena
    git = git_state()
    commit = f"{git['commit'] or 'nogit'}{'-dirty' if git['dirty'] else ''}"
    descriptive_label = f"{args.experiment}@{commit}"
    run_label = args.run_label or settings.remote_run_label or descriptive_label
    public_model = settings.llm_default_model
    if settings.public_opaque_labels and not (args.run_label or settings.remote_run_label):
        run_label = "r" + sha256_text(descriptive_label)[:8]
    if settings.public_opaque_labels:
        public_model = "m" + sha256_text(f"{settings.agent_kind}:{settings.llm_default_model}")[:6]
    system_prompt = SYSTEM_PROMPTS[settings.agent_prompt]
    system_prompt_sha = sha256_text(system_prompt)
    recorder = None
    if not args.no_record:
        recorder = RunRecorder(
            args.experiment,
            {
                "experiment": args.experiment,
                "agent_kind": settings.agent_kind,
                "jev_model": settings.jev_model if settings.agent_kind != "sgr" else None,
                "jev_call_budget": settings.jev_call_budget
                if settings.agent_kind != "sgr"
                else None,
                "jev_attack_threshold": (
                    settings.jev_attack_threshold if settings.agent_kind == "jev_only" else None
                ),
                "jev_stop_threshold": settings.jev_stop_threshold,
                "jev_artifact_policy": settings.jev_artifact_policy,
                "jev_benign_max_entities": settings.jev_benign_max_entities,
                "run_label": run_label,
                "descriptive_label": descriptive_label,
                "public_model": public_model,
                "agent_name": agent_name,
                "arena": arena,
                "model": settings.llm_default_model,
                "response_format": settings.llm_response_format,
                "max_steps": settings.agent_max_steps,
                "max_completion_tokens": settings.llm_max_completion_tokens,
                "agent_prompt": settings.agent_prompt,
                "expand_entity": settings.agent_expand_entity,
                "finish_review": settings.agent_finish_review,
                "payload_policy": settings.agent_payload_policy,
                "payload_v2": settings.payload_v2,
                "review_model": settings.llm_review_model,
                "review_budget_usd": settings.llm_review_budget_usd,
                "run_budget_usd": settings.llm_run_budget_usd,
                "system_prompt_sha": system_prompt_sha,
            },
        )
        print(f"Recording run artifacts to {recorder.directory}", file=sys.stderr)
    print(f"Platform run label {run_label} = {descriptive_label}", file=sys.stderr)
    # Fail before CreateRun: a broken provider would otherwise abort every leased task.
    if settings.agent_kind != "jev_only":
        await llm.preflight()
    if review_llm is not None:
        await review_llm.preflight()
    async with (
        llm,
        RemoteBenchmarkClient(
            endpoint=args.endpoint or settings.scenario_runtime_endpoint,
            token=args.token or settings.scenario_runtime_token.get_secret_value(),
            verify_tls=verify_tls,
            run_label=run_label,
            agent_name=agent_name,
            model_name=public_model,
            arena=arena,
            metadata=(
                {"agent": agent_name, "run": run_label}
                if settings.public_opaque_labels
                else {
                    "agent": agent_name,
                    "implementation": "structured-generation-scenario-runtime-grpc",
                    "model": settings.llm_default_model,
                    "experiment": args.experiment,
                    "agent_kind": settings.agent_kind,
                    "commit": commit,
                    "system_prompt_sha": system_prompt_sha,
                }
            ),
        ) as client,
    ):
        agent: SimpleSGRAgent
        jev = None
        if settings.agent_kind == "sgr":
            agent = SimpleSGRAgent(
                llm,
                max_steps=settings.agent_max_steps,
                recorder=recorder,
                system_prompt=system_prompt,
                expand_entity=settings.agent_expand_entity,
                finish_review=settings.agent_finish_review,
                review_llm=review_llm,
                review_budget_usd=settings.llm_review_budget_usd,
                run_budget_usd=settings.llm_run_budget_usd,
                payload_policy=settings.agent_payload_policy,
                payload_v2=settings.payload_v2,
            )
        else:
            jev = JevClient(
                api_key=settings.llm_api_key.get_secret_value(), model=settings.jev_model
            )
            agent = JevNavigatorAgent(
                jev,
                final_mode=settings.agent_kind,
                llm=llm if settings.agent_kind == "jev_llm" else None,
                call_budget=settings.jev_call_budget,
                attack_threshold=settings.jev_attack_threshold,
                stop_threshold=settings.jev_stop_threshold,
                artifact_policy=settings.jev_artifact_policy,
                benign_max_entities=settings.jev_benign_max_entities,
                payload_v2=settings.payload_v2,
                recorder=recorder,
                run_budget_usd=settings.llm_run_budget_usd,
            )
        try:
            result = await agent.run(client)
        finally:
            if jev is not None:
                await jev.aclose()
    if review_llm is not None:
        await review_llm.aclose()

    print(json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True))


def _raise_keyboard_interrupt(signum: int, frame: object) -> None:
    """Turn SIGTERM into the same graceful shutdown path as Ctrl+C (closes the run)."""
    raise KeyboardInterrupt


def main() -> None:
    """Parse arguments and execute the async remote agent."""
    # Background launches (`nohup ... &`) ignore SIGINT; SIGTERM must still close the run.
    signal.signal(signal.SIGTERM, _raise_keyboard_interrupt)
    signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        asyncio.run(run(build_parser().parse_args()))
    except RunCapacityExceededError as error:
        print(_run_capacity_message(error), file=sys.stderr)
        raise SystemExit(1) from error
    except CompetitionClosedError as error:
        print(
            "The selected competition arena is closed. Check SCENARIO_RUNTIME_ARENA or retry "
            "when the arena opens.",
            file=sys.stderr,
        )
        raise SystemExit(1) from error
    except RemoteRateLimitError as error:
        print(
            "Run starts are temporarily rate-limited. Wait before starting another run.",
            file=sys.stderr,
        )
        raise SystemExit(1) from error
    except RemoteAuthenticationError as error:
        print(
            "The runtime rejected your key. Check SCENARIO_RUNTIME_TOKEN in .env.",
            file=sys.stderr,
        )
        raise SystemExit(1) from error
    except RemoteUnavailableError as error:
        print(
            "Cannot reach the runtime. Check SCENARIO_RUNTIME_ENDPOINT and "
            "SCENARIO_RUNTIME_VERIFY_TLS in .env.",
            file=sys.stderr,
        )
        raise SystemExit(1) from error


def _load_settings() -> Settings:
    """Load settings and explain what is missing instead of raising a raw error.

    Returns:
        Validated settings.
    """
    try:
        return Settings()
    except ValidationError as error:
        missing = [str(item["loc"][0]) for item in error.errors() if item["type"] == "missing"]
        if not missing:
            raise
        print("Missing configuration: " + ", ".join(missing), file=sys.stderr)
        print(
            "Copy .env.example to .env and fill it in. "
            "Runtime address and key: https://bluesec.team/",
            file=sys.stderr,
        )
        raise SystemExit(1) from error


def _run_capacity_message(error: RunCapacityExceededError) -> str:
    """Explain which run limit was hit and what to do about it.

    Args:
        error: Capacity failure reported by the runtime.

    Returns:
        Message for the participant.
    """
    if getattr(error, "reason", None) == "PROCESS_ACTIVE_RUN_LIMIT_REACHED":
        lines = ["The runtime is at its overall capacity right now. This is not your limit."]
    else:
        lines = [
            "You have reached your limit of concurrent runs.",
            "Wait for a running one to finish. If an agent was killed mid-run, its run stays "
            "open until it is released.",
        ]
    return "\n".join(lines)
