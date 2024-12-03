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
        result_frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.results_text = scrolledtext.ScrolledText(result_frame)
        self.results_text.pack(fill="both", expand=True, padx=5, pady=5)

    def analyze_input(self):
        input_data = self.input_text.get("1.0", tk.END).strip()
        asyncio.run(self.process_input(input_data))

    async def process_input(self, input_data: str):
        result = await self.immune_system.immune_response(input_data)
        self.results_text.delete("1.0", tk.END)
        self.results_text.insert("1.0", json.dumps(result, indent=2))

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    immune_system = EnhancedSentientImmunology("config.json")
    gui = SNITGUI(immune_system)
    gui.run()
