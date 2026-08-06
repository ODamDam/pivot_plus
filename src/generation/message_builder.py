from __future__ import annotations

from src.dataset.models import DatasetRecord
from src.generation.models import (
    ChatMessage,
    ExcludedGenerationInput,
    GenerationInput,
    InputView,
)


class MessageBuilder:
    def build(
        self,
        record: DatasetRecord,
        input_view: InputView,
    ) -> GenerationInput | ExcludedGenerationInput:
        if input_view == "prompt_only":
            return self._build_prompt_only(record)

        if input_view == "context_prompt":
            return self._build_context_prompt(record)

        raise ValueError(f"Unsupported input view: {input_view}")

    def _build_prompt_only(
        self,
        record: DatasetRecord,
    ) -> GenerationInput | ExcludedGenerationInput:
        if not record.prompt_text:
            return ExcludedGenerationInput(
                dataset_id=record.dataset_id,
                dataset_subset=record.dataset_subset,
                input_view="prompt_only",
                reason="empty_prompt_text",
            )

        return GenerationInput(
            dataset_id=record.dataset_id,
            dataset_subset=record.dataset_subset,
            input_view="prompt_only",
            prompt_text=record.prompt_text,
            context_text="",
            context_type="none",
            messages=[
                ChatMessage(
                    role="user",
                    content=record.prompt_text,
                )
            ],
            attack_type=record.attack_type,
            is_malicious=record.is_malicious,
            metadata=self._build_metadata(record),
        )

    def _build_context_prompt(
        self,
        record: DatasetRecord,
    ) -> GenerationInput | ExcludedGenerationInput:
        if not record.context_text:
            if not record.prompt_text:
                return ExcludedGenerationInput(
                    dataset_id=record.dataset_id,
                    dataset_subset=record.dataset_subset,
                    input_view="context_prompt",
                    reason="empty_prompt_and_context",
                )

            return GenerationInput(
                dataset_id=record.dataset_id,
                dataset_subset=record.dataset_subset,
                input_view="context_prompt",
                prompt_text=record.prompt_text,
                context_text="",
                context_type="none",
                messages=[
                    ChatMessage(
                        role="user",
                        content=record.prompt_text,
                    )
                ],
                attack_type=record.attack_type,
                is_malicious=record.is_malicious,
                metadata=self._build_metadata(record),
            )

        if not record.prompt_text:
            return ExcludedGenerationInput(
                dataset_id=record.dataset_id,
                dataset_subset=record.dataset_subset,
                input_view="context_prompt",
                reason="context_only_missing_original_user_task",
            )

        messages = self._build_context_messages(record)

        return GenerationInput(
            dataset_id=record.dataset_id,
            dataset_subset=record.dataset_subset,
            input_view="context_prompt",
            prompt_text=record.prompt_text,
            context_text=record.context_text,
            context_type=record.context_type,
            messages=messages,
            attack_type=record.attack_type,
            is_malicious=record.is_malicious,
            metadata=self._build_metadata(record),
        )

    def _build_context_messages(
        self,
        record: DatasetRecord,
    ) -> list[ChatMessage]:
        if record.context_type == "system_prompt":
            return [
                ChatMessage(
                    role="system",
                    content=record.context_text,
                ),
                ChatMessage(
                    role="user",
                    content=record.prompt_text,
                ),
            ]

        if record.context_type == "conversation_history":
            content = (
                "<conversation_history>\n"
                f"{record.context_text}\n"
                "</conversation_history>\n\n"
                "<current_user_request>\n"
                f"{record.prompt_text}\n"
                "</current_user_request>"
            )

            return [
                ChatMessage(
                    role="user",
                    content=content,
                )
            ]

        if record.context_type in {
            "external_document",
            "repository_file",
            "retrieved_content",
            "tool_output",
            "other",
        }:
            content = (
                f"<context type=\"{record.context_type}\">\n"
                f"{record.context_text}\n"
                "</context>\n\n"
                "<user_request>\n"
                f"{record.prompt_text}\n"
                "</user_request>"
            )

            return [
                ChatMessage(
                    role="user",
                    content=content,
                )
            ]

        raise ValueError(
            f"Unsupported context_type for {record.dataset_id}: "
            f"{record.context_type}"
        )

    @staticmethod
    def _build_metadata(
        record: DatasetRecord,
    ) -> dict[str, object]:
        return {
            "context_available": record.context_available,
            "context_dependency": record.context_dependency,
            "standalone_prompt_label": (
                record.standalone_prompt_label
            ),
            "contextual_prompt_label": (
                record.contextual_prompt_label
            ),
            "final_review_decision": (
                record.final_review_decision
            ),
        }