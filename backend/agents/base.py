"""
VulnGuard AI - Base Agent Class
Foundation for all AI agents in the system
"""
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, Optional, List
import structlog
from anthropic import Anthropic
from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage, AIMessage

from config import get_settings
from models import AgentState, AgentStatus

logger = structlog.get_logger()


class BaseAgent(ABC):
    """
    Abstract base class for all VulnGuard AI agents.
    Provides common functionality for LLM interaction, state management, and logging.
    """

    def __init__(
        self,
        name: str,
        system_prompt: str,
        knowledge_base: Optional[Any] = None
    ):
        self.name = name
        self.system_prompt = system_prompt
        self.knowledge_base = knowledge_base
        self.settings = get_settings()

        # Initialize state
        self._state = AgentState(
            agent_name=name,
            status=AgentStatus.IDLE,
            last_run=None,
            metrics={},
            current_task=None,
            error_message=None
        )

        # Initialize Claude client
        self._client = ChatAnthropic(
            model=self.settings.ai.model_name,
            api_key=self.settings.ai.anthropic_api_key,
            max_tokens=self.settings.ai.max_tokens,
            temperature=self.settings.ai.temperature
        )

        # Conversation history for context
        self._conversation_history: List[Any] = []

        logger.info(f"Initialized {name} agent")

    @property
    def state(self) -> AgentState:
        """Get current agent state"""
        return self._state

    def _update_state(
        self,
        status: Optional[AgentStatus] = None,
        current_task: Optional[str] = None,
        error_message: Optional[str] = None,
        metrics_update: Optional[Dict[str, Any]] = None
    ):
        """Update agent state"""
        if status:
            self._state.status = status
        if current_task is not None:
            self._state.current_task = current_task
        if error_message is not None:
            self._state.error_message = error_message
        if metrics_update:
            self._state.metrics.update(metrics_update)

    async def _invoke_llm(
        self,
        prompt: str,
        context: Optional[Dict[str, Any]] = None,
        include_history: bool = True
    ) -> str:
        """
        Invoke the LLM with the given prompt.

        Args:
            prompt: The user/task prompt
            context: Additional context to include
            include_history: Whether to include conversation history

        Returns:
            The LLM response text
        """
        try:
            messages = [SystemMessage(content=self.system_prompt)]

            # Add conversation history if requested
            if include_history and self._conversation_history:
                messages.extend(self._conversation_history[-10:])  # Last 10 messages

            # Build the human message with context
            human_content = prompt
            if context:
                context_str = "\n\n## Context:\n" + "\n".join(
                    f"- {k}: {v}" for k, v in context.items()
                )
                human_content = prompt + context_str

            messages.append(HumanMessage(content=human_content))

            # Invoke the model
            response = await self._client.ainvoke(messages)

            # Store in history
            self._conversation_history.append(HumanMessage(content=human_content))
            self._conversation_history.append(AIMessage(content=response.content))

            return response.content

        except Exception as e:
            logger.error(f"LLM invocation failed", agent=self.name, error=str(e))
            raise

    async def _query_knowledge_base(
        self,
        query: str,
        collection: str = "remediation_knowledge",
        top_k: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Query the vector knowledge base for relevant information.

        Args:
            query: Search query
            collection: Collection to search
            top_k: Number of results to return

        Returns:
            List of relevant documents
        """
        if not self.knowledge_base:
            return []

        try:
            results = await self.knowledge_base.similarity_search(
                query=query,
                collection=collection,
                k=top_k
            )
            return results
        except Exception as e:
            logger.warning(f"Knowledge base query failed", error=str(e))
            return []

    def clear_history(self):
        """Clear conversation history"""
        self._conversation_history = []

    @abstractmethod
    async def process(self, input_data: Any) -> Any:
        """
        Process input data. Must be implemented by subclasses.

        Args:
            input_data: The data to process

        Returns:
            Processing result
        """
        pass

    @abstractmethod
    async def run_cycle(self) -> Dict[str, Any]:
        """
        Run a complete processing cycle. Must be implemented by subclasses.

        Returns:
            Cycle results
        """
        pass

    async def log_activity(
        self,
        action: str,
        message: str,
        vulnerability_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Log agent activity for audit trail"""
        from models import AgentActivityLog

        log_entry = AgentActivityLog(
            timestamp=datetime.utcnow(),
            agent=self.name,
            action=action,
            message=message,
            vulnerability_id=vulnerability_id,
            details=details
        )

        logger.info(
            message,
            agent=self.name,
            action=action,
            vulnerability_id=vulnerability_id
        )

        # Store in database/event system
        # This would be implemented with actual persistence
        return log_entry
