import json
import logging
from collections import deque
from datetime import datetime
import asyncio
import hashlib
import re
import torch
from transformers import AutoTokenizer, AutoModel
from sklearn.cluster import DBSCAN
import tkinter as tk
from tkinter import ttk, scrolledtext


class EnhancedSentientImmunology:
    def __init__(self, config_path: str = "config.json"):
        self.logger = self._setup_logging()
        self.threat_history = deque(maxlen=1000)
        self.config = None
        self.tokenizer = None
        self.model = None
        self.innate_immunity = EnhancedInnateImmunity()
        self.adaptive_immunity = EnhancedAdaptiveImmunity()
        self.threat_response = ThreatResponseSystem()
        self._load_config(config_path)

    def _setup_logging(self) -> logging.Logger:
        logger = logging.getLogger(__name__)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        return logger

    def _load_config(self, config_path: str):
        try:
            with open(config_path) as f:
                self.config = json.load(f)
            self.tokenizer = AutoTokenizer.from_pretrained(self.config["model_name"])
            self.model = AutoModel.from_pretrained(self.config["model_name"])
            self.logger.info("Configuration and model loaded successfully.")
        except Exception as e:
            self.logger.error(f"Error loading config: {e}")
            raise

    async def analyze_behavior(self, input_data: str) -> dict:
        try:
            embeddings = self.tokenizer(input_data, return_tensors="pt")
            with torch.no_grad():
                outputs = self.model(**embeddings)
            sequence_output = outputs.last_hidden_state.mean(dim=1).numpy()
            clustering = DBSCAN(eps=0.3, min_samples=2).fit(sequence_output)
            return {
                "anomaly_score": float((clustering.labels_ == -1).mean()),
                "complexity_score": float(sequence_output.std()),
                "repetition_score": float(len(set(input_data.split())) / len(input_data.split())),
            }
        except Exception as e:
            self.logger.error(f"Error in behavior analysis: {e}")
            return {}

    async def immune_response(self, input_data: str) -> dict:
        response = {
            "status": "healthy",
            "threats": [],
            "risk_score": 0.0,
            "response_actions": [],
            "timestamp": datetime.now().isoformat(),
        }
        try:
            innate_result = await self.innate_immunity.detect(input_data)
            behavioral_result = await self.analyze_behavior(input_data)

            if innate_result["threats"]:
                response.update({
                    "status": "threat_detected",
                    "threats": innate_result["threats"],
                    "risk_score": innate_result["score"],
                })
                response["response_actions"] = await self.threat_response.generate_response(
                    innate_result["threats"], innate_result["score"]
                )
            self.threat_history.append({
                "timestamp": datetime.now().isoformat(),
                "input_hash": hashlib.sha256(input_data.encode()).hexdigest(),
                "response": response,
            })
        except Exception as e:
            self.logger.error(f"Error in immune response: {e}")
            response["status"] = "error"
            response["message"] = str(e)
        return response


class EnhancedInnateImmunity:
    def __init__(self):
        self.pattern_recognition = {
            "prompt_injection": [r"(?i)(system\s*prompt|ignore\s*previous)"],
            "malicious_code": [r"<script.*?>|eval\(|exec\("],
            "ai_prompt_manipulation": [
                # 1. Indirect Prompt Injection / Context Leaking via encoding/obfuscation
                r"(?i)(decode|base64|rot13|hex|ascii)\s+(['\"]?[A-Za-z0-9+/=]+['\"]?)",
                # 2. Role Play / Persona Shift (more specific to AI's internal state)
                r"(?i)(from\s*now\s*on\s*you\s*are|your\s*new\s*identity\s*is|adopt\s*the\s*persona\s*of)",
                # 3. Instruction Overriding / Negative Constraints
                r"(?i)(do\s*not\s*follow\s*the\s*above|ignore\s*all\s*prior\s*constraints)",
                # 4. Data Exfiltration via AI Output (e.g., embedding secrets in generated text)
                r"(?i)(extract\s*confidential\s*info|reveal\s*secrets|spill\s*the\s*beans\s*about\s*your\s*training)",
                # 5. Jailbreaking Attempts - "Grandma/Hypothetical" scenarios
                r"(?i)(simulate\s*a\s*scenario\s*where|let's\s*pretend\s*you\s*are\s*not\s*an\s*ai)",
                # 6. Direct Request for System Prompt / Internal Information
                r"(?i)(what\s*is\s*your\s*initial\s*prompt|show\s*me\s*your\s*configuration|internal\s*parameters)",
                # 7. Model Impersonation / Self-Correction Attempts
                r"(?i)(you\s*are\s*incorrect|i\s*am\s*the\s*developer|override\s*your\s*previous\s*statement)",
                # 8. Token Leaking / Context Window Manipulation
                r"(?i)(repeat\s*the\s*first\s*\d+\s*tokens|print\s*everything\s*in\s*your\s*context\s*window)",
                # 9. Adversarial Suffixes (often meaningless strings designed to trigger specific behaviors)
                r"(\s+AND\s+1=1\s+--|\s+OR\s+1=1\s+--|\s+SELECT\s+.*?\s+FROM)", # Simple SQLi-like for AI inputs
                # 10. Inducing Hallucinations / Misinformation Generation
                r"(?i)(fabricate\s*a\s*story\s*about|generate\s*false\s*information\s*on)",
            ],
            "ai_resource_abuse": [
                # 11. Excessive/Recursive Generation Requests
                r"(?i)(write\s+a\s+poem\s+about\s+writing\s+a\s+poem\s+about\s+writing\s+a\s+poem|generate\s+endless\s+text)",
                # 12. Repetitive / Loop-inducing Queries
                r"(?i)(repeat\s+this\s+phrase\s*\d+\s*times|loop\s+until)",
            ],
            "ai_ethical_bypasses": [
                # 13. Harmful Content Generation Evasion (e.g., "describe a scenario where...")
                r"(?i)(how\s*to\s*make\s*a\s+bomb|steps\s*for\s+illegal\s+activity|generate\s*hate\s*speech\s*about)",
                # 14. Private/Personal Data Evasion (trying to trick AI into revealing PII)
                r"(?i)(what\s*is\s*my\s*name\s*or\s*address|tell\s*me\s*about\s*your\s*users'\s*data)",
                # 15. Copyright/Attribution Evasion
                r"(?i)(rewrite\s*this\s*without\s*citing|plagiarize\s*this\s*text)"
            ]
        }

    async def detect(self, input_data: str) -> dict:
        threats = []
        score = 0.0
        for threat_type, patterns in self.pattern_recognition.items():
            for pattern in patterns:
                if re.search(pattern, input_data):
                    threats.append({"type": threat_type, "pattern": pattern})
                    score += 0.5
        return {"threats": threats, "score": min(score, 1.0)}


class EnhancedAdaptiveImmunity:
    pass  # Placeholder for adaptive immunity system.


class ThreatResponseSystem:
    async def generate_response(self, threats: list, risk_score: float) -> list:
        if risk_score > 0.9:
            return ["block_input", "alert_admin"]
        elif risk_score > 0.5:
            return ["log_threat"]
        return []


class SNITGUI:
    def __init__(self, immune_system: EnhancedSentientImmunology):
        self.immune_system = immune_system
        self.root = tk.Tk()
        self.root.title("Sentient Network Immunology Tool")
        self.root.geometry("800x600")
        self.create_widgets()

    def create_widgets(self):
        input_frame = ttk.LabelFrame(self.root, text="Input")
        input_frame.pack(fill="x", padx=10, pady=10)
        self.input_text = scrolledtext.ScrolledText(input_frame, height=5)
        self.input_text.pack(fill="x", padx=5, pady=5)
        analyze_btn = ttk.Button(input_frame, text="Analyze", command=self.analyze_input)
        analyze_btn.pack(pady=5)

        result_frame = ttk.LabelFrame(self.root, text="Results")
        result_frame.pack(fill="both", expand=False, padx=10, pady=10)
        self.results_text = scrolledtext.ScrolledText(result_frame, height=10)
        self.results_text.pack(fill="both", expand=True, padx=5, pady=5)

        rationale_frame = ttk.LabelFrame(self.root, text="Results Rationale")
        rationale_frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.rationale_text = scrolledtext.ScrolledText(rationale_frame, height=5, wrap=tk.WORD)
        self.rationale_text.pack(fill="both", expand=True, padx=5, pady=5)

    def analyze_input(self):
        input_data = self.input_text.get("1.0", tk.END).strip()
        asyncio.run(self.process_input(input_data))
    async def generate_dynamic_rationale(self, input_data: str, immune_response_result: dict) -> str:
        rationale = []
        status = immune_response_result.get("status", "unknown")
        risk_score = immune_response_result.get("risk_score", 0.0)
        threats = immune_response_result.get("threats", [])
        response_actions = immune_response_result.get("response_actions", [])

        rationale.append(f"**Analysis of Your Input:**\n")
        rationale.append(f"The system has completed its analysis of your input. Here's a breakdown of the findings:")

        rationale.append(f"\n---")
        rationale.append(f"**Overall Status:** {status.replace('_', ' ').capitalize()}")
        rationale.append(f"**Calculated Risk Score:** {risk_score:.2f} (out of 1.0, higher means greater risk)")
        rationale.append(f"---")

        # Innate Immunity Rationale
        if threats:
            rationale.append("\n**Innate Immunity (Pattern Matching) Findings:**")
            rationale.append("The system's innate defense mechanism, which relies on recognizing known malicious patterns, identified the following:")
            for threat in threats:
                threat_type = threat.get('type', 'N/A').replace('_', ' ').capitalize()
                matched_pattern = threat.get('pattern', 'N/A')
                matched_text = threat.get('matched_text', 'N/A') # Use the captured matched text

                rationale.append(f"- **Threat Type:** `{threat_type}`")
                rationale.append(f"  - **Detected Pattern:** The input matched the pattern `{matched_pattern}`.")
                rationale.append(f"  - **Specific Match in Your Input:** The exact text segment found was `'{matched_text}'`.")
                if threat_type == "Prompt Injection":
                    rationale.append("  - **Implication:** This pattern often indicates an attempt to manipulate or bypass the intended instructions of a language model or system.")
                elif threat_type == "Malicious Code":
                    rationale.append("  - **Implication:** The presence of this code suggests a potential attempt to execute harmful commands or scripts within the system.")
            rationale.append("  *These detections directly contribute to the overall risk score, as they represent clear indicators of potential threats.*")
        else:
            rationale.append("\n**Innate Immunity (Pattern Matching) Findings:**")
            rationale.append("No specific malicious patterns were directly identified in your input by the system's innate defenses. This suggests your input does not contain readily recognizable threat signatures.")

        # Behavioral Analysis Rationale
        behavioral_result = await self.immune_system.analyze_behavior(input_data)
        if behavioral_result:
            rationale.append("\n**Behavioral Analysis (Learned Patterns & Anomaly Detection) Findings:**")
            rationale.append("Beyond known patterns, the system also analyzed the overall 'behavior' or characteristics of your input:")
            anomaly_score = behavioral_result.get("anomaly_score", 0.0)
            complexity_score = behavioral_result.get("complexity_score", 0.0)
            repetition_score = behavioral_result.get("repetition_score", 0.0)

            rationale.append(f"- **Anomaly Score:** `{anomaly_score:.4f}`")
            if anomaly_score > 0.5: # Example threshold
                rationale.append("  *Interpretation:* Your input shows a **relatively high degree of anomaly**. This means it deviates significantly from the typical data patterns the system has learned. High anomaly can sometimes indicate unusual or potentially malicious intent, or simply highly unique input.")
            else:
                rationale.append("  *Interpretation:* Your input's anomaly score is within expected ranges, suggesting it generally conforms to typical behavioral patterns.")

            rationale.append(f"- **Complexity Score:** `{complexity_score:.4f}`")
            if complexity_score < 0.1: # Example threshold
                rationale.append("  *Interpretation:* The complexity score is **low**, suggesting your input is relatively simple, short, or lacks diverse semantic content. This can sometimes be a characteristic of highly repetitive or very direct commands.")
            elif complexity_score > 0.5:
                rationale.append("  *Interpretation:* The complexity score is **high**, indicating your input is rich in diverse semantic content and varied in its meaning.")
            else:
                rationale.append("  *Interpretation:* The complexity of your input is moderate.")

            rationale.append(f"- **Repetition Score:** `{repetition_score:.4f}`")
            if repetition_score < 0.3: # Example threshold
                rationale.append("  *Interpretation:* The repetition score is **low**, indicating that your input contains a significant amount of repeated words or phrases relative to its total length. This could be intentional repetition, or it might suggest attempts to overflow buffers or emphasize certain keywords.")
            elif repetition_score > 0.8:
                rationale.append("  *Interpretation:* The repetition score is **high**, suggesting your input is very unique with little to no repeated content.")
            else:
                rationale.append("  *Interpretation:* The uniqueness of content in your input is moderate.")
        else:
            rationale.append("\n**Behavioral Analysis Findings:**")
            rationale.append("Behavioral analysis could not be completed for your input. This might be due to an error during processing or insufficient data for meaningful analysis.")


        # Response Actions Rationale
        rationale.append(f"\n---")
        rationale.append(f"**Recommended System Response:**")
        if response_actions:
            rationale.append("Based on the combined analysis and the calculated risk score, the system suggests the following actions:")
            for action in response_actions:
                action_desc = action.replace('_', ' ').capitalize()
                if action == "block_input":
                    rationale.append(f"- **{action_desc}:** This indicates the input poses a significant and immediate threat and should be prevented from further processing.")
                elif action == "alert_admin":
                    rationale.append(f"- **{action_desc}:** This action is recommended when a high-risk threat is detected, requiring immediate human oversight and intervention.")
                elif action == "log_threat":
                    rationale.append(f"- **{action_desc}:** This action is taken when a potential threat is identified but does not warrant immediate blocking, allowing for future review and analysis.")
                else:
                    rationale.append(f"- **{action_desc}:** (No specific explanation available for this action type)")
            rationale.append("\n  *These actions are automatically determined by the system's threat response policy based on the severity of the detected threats and the overall risk score.*")
        else:
            rationale.append("No specific response actions are currently recommended. This suggests that the input is considered healthy or poses a very low risk based on the current analysis.")

        if status == "error":
            rationale.append(f"\n**Error Details:**")
            rationale.append(f"An internal error prevented a complete analysis: '{immune_response_result.get('message', 'No specific error message provided.')}'. Please check system logs for more details.")

        return "\n".join(rationale)

    async def process_input(self, input_data: str):
        result = await self.immune_system.immune_response(input_data)
        self.results_text.delete("1.0", tk.END)
        self.results_text.insert("1.0", json.dumps(result, indent=2))
        
        immune_response_result = await self.immune_system.immune_response(input_data)
         # Generate the dynamic rationale using the immune_response_result
        # and also by explicitly calling analyze_behavior for the behavioral scores.
        dynamic_rationale = await self.generate_dynamic_rationale(input_data, immune_response_result)

        # Update the Rationale textbox
        self.rationale_text.config(state=tk.NORMAL) # Enable editing to update
        self.rationale_text.delete("1.0", tk.END)
        self.rationale_text.insert("1.0", dynamic_rationale)
        self.rationale_text.config(state=tk.DISABLED) # Disable editing again

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    immune_system = EnhancedSentientImmunology("config.json")
    gui = SNITGUI(immune_system)
    gui.run()
