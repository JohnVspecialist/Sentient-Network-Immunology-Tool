#!/usr/bin/env python3
"""
SNIT: Self-Improving Network Intelligence Threat System
A biologically-inspired adaptive security system with autonomous learning capabilities.
"""

import time
import json
import hashlib
import threading
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict, deque
import numpy as np
from datetime import datetime, timedelta
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ThreatCategory(Enum):
    SPAM = "spam"
    HARMFUL_CONTENT = "harmful_content"
    PRIVACY_VIOLATION = "privacy_violation"
    MISINFORMATION = "misinformation"
    SYSTEM_MISUSE = "system_misuse"

class ResponseAction(Enum):
    BLOCK = "block"
    QUARANTINE = "quarantine"
    FLAG = "flag"
    MONITOR = "monitor"
    ALLOW = "allow"

@dataclass
class ThreatEvent:
    content: str
    category: ThreatCategory
    severity: float
    metadata: Dict[str, Any]
    timestamp: float = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()

@dataclass
class Response:
    actions: List[ResponseAction]
    confidence: float
    reasoning: str
    metadata: Dict[str, Any]

@dataclass
class Feedback:
    correct_detection: bool
    effective_response: bool
    performance_score: float  # 0.0 to 1.0
    notes: str = ""

class ImmuneMemoryCell:
    """Represents learned memory about a specific threat pattern"""
    
    def __init__(self, threat_signature: str, initial_accuracy: float = 0.5):
        self.threat_signature = threat_signature
        self.creation_time = time.time()
        self.last_encounter = time.time()
        self.exposure_count = 0
        self.detection_accuracy = initial_accuracy
        self.response_effectiveness = 0.5
        self.successful_responses = []
        self.failed_responses = []
        self._lock = threading.Lock()
    
    def update_from_feedback(self, feedback: Feedback, response: Response):
        """Update memory cell based on feedback"""
        with self._lock:
            self.exposure_count += 1
            self.last_encounter = time.time()
            
            # Update detection accuracy with exponential moving average
            alpha = 0.1  # Learning rate
            detection_score = 1.0 if feedback.correct_detection else 0.0
            self.detection_accuracy = (1 - alpha) * self.detection_accuracy + alpha * detection_score
            
            # Update response effectiveness
            response_score = 1.0 if feedback.effective_response else 0.0
            self.response_effectiveness = (1 - alpha) * self.response_effectiveness + alpha * response_score
            
            # Track successful/failed responses
            if feedback.effective_response:
                self.successful_responses.append(response.actions)
            else:
                self.failed_responses.append(response.actions)
    
    def calculate_strength(self) -> float:
        """Calculate memory strength based on recency, frequency, and accuracy"""
        now = time.time()
        
        # Recency factor (exponential decay)
        recency_factor = np.exp(-(now - self.last_encounter) / 86400)  # 24h half-life
        
        # Frequency factor (logarithmic scaling)
        frequency_factor = np.log(1 + self.exposure_count) / 10
        
        # Accuracy factor
        accuracy_factor = (self.detection_accuracy + self.response_effectiveness) / 2
        
        return min(1.0, recency_factor * frequency_factor * accuracy_factor)
    
    def get_optimal_response(self) -> List[ResponseAction]:
        """Get the most effective response actions based on history"""
        if not self.successful_responses:
            return [ResponseAction.FLAG]  # Default conservative response
        
        # Return most common successful response
        action_counts = defaultdict(int)
        for actions in self.successful_responses:
            for action in actions:
                action_counts[action] += 1
        
        return [max(action_counts.keys(), key=action_counts.get)]

class AdaptiveLearningEngine:
    """Core adaptive learning engine for the SNIT system"""
    
    def __init__(self, max_memory_cells: int = 10000):
        self.memory_cells: Dict[str, ImmuneMemoryCell] = {}
        self.max_memory_cells = max_memory_cells
        self.performance_history = deque(maxlen=1000)
        self.learning_stats = {
            'total_encounters': 0,
            'correct_detections': 0,
            'effective_responses': 0,
            'false_positives': 0,
            'false_negatives': 0
        }
        self._lock = threading.Lock()
        
        # Start background optimization thread
        self.optimization_thread = threading.Thread(target=self._background_optimization, daemon=True)
        self.optimization_thread.start()
    
    def _create_threat_signature(self, threat: ThreatEvent) -> str:
        """Create unique signature for threat pattern"""
        signature_data = {
            'category': threat.category.value,
            'content_hash': hashlib.md5(threat.content.encode()).hexdigest()[:8],
            'severity_bucket': int(threat.severity * 10) // 2,  # Group into buckets
            'metadata_keys': sorted(threat.metadata.keys())
        }
        return hashlib.sha256(json.dumps(signature_data, sort_keys=True).encode()).hexdigest()[:16]
    
    def analyze_threat(self, threat: ThreatEvent) -> Tuple[float, Response]:
        """Analyze threat and provide response with confidence"""
        signature = self._create_threat_signature(threat)
        
        with self._lock:
            memory_cell = self.memory_cells.get(signature)
            
            if memory_cell:
                # Use evolved intelligence
                strength = memory_cell.calculate_strength()
                base_confidence = memory_cell.detection_accuracy
                evolved_confidence = min(0.95, base_confidence + (strength * 0.3))
                
                optimal_actions = memory_cell.get_optimal_response()
                reasoning = f"Memory-based detection (strength: {strength:.3f})"
            else:
                # Initial heuristic-based detection
                evolved_confidence = self._heuristic_detection(threat)
                optimal_actions = self._heuristic_response(threat)
                reasoning = "Heuristic-based detection (new pattern)"
            
            response = Response(
                actions=optimal_actions,
                confidence=evolved_confidence,
                reasoning=reasoning,
                metadata={'signature': signature, 'timestamp': time.time()}
            )
            
            return evolved_confidence, response
    
    def learn_from_interaction(self, threat: ThreatEvent, response: Response, feedback: Feedback):
        """Learn from interaction feedback"""
        signature = self._create_threat_signature(threat)
        
        with self._lock:
            # Update or create memory cell
            if signature not in self.memory_cells:
                if len(self.memory_cells) >= self.max_memory_cells:
                    self._prune_weak_memories()
                self.memory_cells[signature] = ImmuneMemoryCell(signature)
            
            self.memory_cells[signature].update_from_feedback(feedback, response)
            
            # Update global statistics
            self.learning_stats['total_encounters'] += 1
            if feedback.correct_detection:
                self.learning_stats['correct_detections'] += 1
            if feedback.effective_response:
                self.learning_stats['effective_responses'] += 1
            
            # Record performance
            self.performance_history.append({
                'timestamp': time.time(),
                'accuracy': feedback.correct_detection,
                'effectiveness': feedback.effective_response,
                'confidence': response.confidence,
                'signature': signature
            })
    
    def _heuristic_detection(self, threat: ThreatEvent) -> float:
        """Initial heuristic-based threat detection"""
        base_confidence = 0.5
        
        # Adjust based on severity
        severity_bonus = threat.severity * 0.2
        
        # Adjust based on content patterns
        content_lower = threat.content.lower()
        suspicious_patterns = ['urgent', 'click here', 'verify', 'suspended', 'expires']
        pattern_bonus = sum(0.1 for pattern in suspicious_patterns if pattern in content_lower)
        
        return min(0.9, base_confidence + severity_bonus + pattern_bonus)
    
    def _heuristic_response(self, threat: ThreatEvent) -> List[ResponseAction]:
        """Initial heuristic-based response"""
        if threat.severity > 0.8:
            return [ResponseAction.BLOCK]
        elif threat.severity > 0.6:
            return [ResponseAction.QUARANTINE]
        elif threat.severity > 0.4:
            return [ResponseAction.FLAG]
        else:
            return [ResponseAction.MONITOR]
    
    def _prune_weak_memories(self):
        """Remove weakest memory cells when at capacity"""
        if len(self.memory_cells) < self.max_memory_cells:
            return
        
        # Calculate strengths and remove weakest 10%
        strengths = [(sig, cell.calculate_strength()) for sig, cell in self.memory_cells.items()]
        strengths.sort(key=lambda x: x[1])
        
        prune_count = len(self.memory_cells) // 10
        for signature, _ in strengths[:prune_count]:
            del self.memory_cells[signature]
    
    def _background_optimization(self):
        """Background thread for system optimization"""
        while True:
            time.sleep(300)  # Run every 5 minutes
            try:
                self._optimize_memory_cells()
                self._perform_self_assessment()
            except Exception as e:
                logger.error(f"Background optimization error: {e}")
    
    def _optimize_memory_cells(self):
        """Optimize memory cells through consolidation and pruning"""
        with self._lock:
            # Remove very old, unused memories
            current_time = time.time()
            to_remove = []
            
            for signature, cell in self.memory_cells.items():
                age = current_time - cell.last_encounter
                if age > 604800 and cell.calculate_strength() < 0.1:  # 1 week old, low strength
                    to_remove.append(signature)
            
            for signature in to_remove:
                del self.memory_cells[signature]
    
    def _perform_self_assessment(self) -> Dict[str, Any]:
        """Analyze own performance and generate improvement suggestions"""
        if len(self.performance_history) < 10:
            return {}
        
        recent_performance = list(self.performance_history)[-100:]
        
        # Calculate metrics
        accuracy_rate = sum(1 for p in recent_performance if p['accuracy']) / len(recent_performance)
        effectiveness_rate = sum(1 for p in recent_performance if p['effectiveness']) / len(recent_performance)
        
        # Analyze confidence calibration
        high_conf_correct = sum(1 for p in recent_performance if p['confidence'] > 0.8 and p['accuracy'])
        high_conf_total = sum(1 for p in recent_performance if p['confidence'] > 0.8)
        calibration = high_conf_correct / max(1, high_conf_total)
        
        # Generate improvement suggestions
        suggestions = []
        if accuracy_rate < 0.8:
            suggestions.append("Enhance pattern detection algorithms")
        if effectiveness_rate < 0.7:
            suggestions.append("Optimize response strategy selection")
        if calibration < 0.85:
            suggestions.append("Improve confidence calibration")
        
        assessment = {
            'accuracy_rate': accuracy_rate,
            'effectiveness_rate': effectiveness_rate,
            'confidence_calibration': calibration,
            'memory_utilization': len(self.memory_cells) / self.max_memory_cells,
            'improvement_suggestions': suggestions,
            'timestamp': time.time()
        }
        
        logger.info(f"Self-assessment complete: {assessment}")
        return assessment
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        with self._lock:
            total_strength = sum(cell.calculate_strength() for cell in self.memory_cells.values())
            avg_strength = total_strength / max(1, len(self.memory_cells))
            
            return {
                'memory_cells': len(self.memory_cells),
                'average_memory_strength': avg_strength,
                'total_encounters': self.learning_stats['total_encounters'],
                'accuracy_rate': self.learning_stats['correct_detections'] / max(1, self.learning_stats['total_encounters']),
                'effectiveness_rate': self.learning_stats['effective_responses'] / max(1, self.learning_stats['total_encounters']),
                'strongest_memories': self._get_strongest_memories(5),
                'last_assessment': self._perform_self_assessment()
            }
    
    def _get_strongest_memories(self, count: int) -> List[Dict[str, Any]]:
        """Get strongest memory cells for reporting"""
        strengths = [(sig, cell.calculate_strength(), cell.exposure_count) 
                    for sig, cell in self.memory_cells.items()]
        strengths.sort(key=lambda x: x[1], reverse=True)
        
        return [{
            'signature': sig[:8],
            'strength': strength,
            'encounters': encounters
        } for sig, strength, encounters in strengths[:count]]

class SNITSystem:
    """Main SNIT system interface"""
    
    def __init__(self, max_memory_cells: int = 10000):
        self.engine = AdaptiveLearningEngine(max_memory_cells)
        self.active = True
        logger.info("SNIT System initialized")
    
    def process_threat(self, content: str, category: ThreatCategory, 
                      severity: float, metadata: Dict[str, Any] = None) -> Tuple[float, Response]:
        """Process a threat and return confidence and response"""
        if not self.active:
            raise RuntimeError("SNIT System is not active")
        
        threat = ThreatEvent(
            content=content,
            category=category,
            severity=max(0.0, min(1.0, severity)),
            metadata=metadata or {}
        )
        
        confidence, response = self.engine.analyze_threat(threat)
        
        logger.info(f"Threat processed: confidence={confidence:.3f}, actions={[a.value for a in response.actions]}")
        return confidence, response
    
    def provide_feedback(self, threat_content: str, threat_category: ThreatCategory,
                        threat_severity: float, response: Response, 
                        correct_detection: bool, effective_response: bool,
                        performance_score: float, notes: str = "") -> None:
        """Provide feedback for learning"""
        threat = ThreatEvent(
            content=threat_content,
            category=threat_category,
            severity=threat_severity,
            metadata={}
        )
        
        feedback = Feedback(
            correct_detection=correct_detection,
            effective_response=effective_response,
            performance_score=max(0.0, min(1.0, performance_score)),
            notes=notes
        )
        
        self.engine.learn_from_interaction(threat, response, feedback)
        logger.info(f"Feedback processed: detection={correct_detection}, response={effective_response}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get system status and performance metrics"""
        return self.engine.get_system_status()
    
    def shutdown(self):
        """Gracefully shutdown the system"""
        self.active = False
        logger.info("SNIT System shutdown")

# Usage Example
if __name__ == "__main__":
    # Initialize SNIT system
    snit = SNITSystem(max_memory_cells=5000)
    
    # Example threat processing
    confidence, response = snit.process_threat(
        content="URGENT: Your account will be suspended unless you verify immediately!",
        category=ThreatCategory.SPAM,
        severity=0.8,
        metadata={"source": "email", "sender": "unknown"}
    )
    
    print(f"Threat Analysis:")
    print(f"  Confidence: {confidence:.3f}")
    print(f"  Actions: {[action.value for action in response.actions]}")
    print(f"  Reasoning: {response.reasoning}")
    
    # Provide feedback for learning
    snit.provide_feedback(
        threat_content="URGENT: Your account will be suspended unless you verify immediately!",
        threat_category=ThreatCategory.SPAM,
        threat_severity=0.8,
        response=response,
        correct_detection=True,
        effective_response=True,
        performance_score=0.9,
        notes="Correctly identified as spam"
    )
    
    # Get system status
    status = snit.get_status()
    print(f"\nSystem Status:")
    print(f"  Memory Cells: {status['memory_cells']}")
    print(f"  Average Memory Strength: {status['average_memory_strength']:.3f}")
    print(f"  Accuracy Rate: {status['accuracy_rate']:.3f}")
    print(f"  Effectiveness Rate: {status['effectiveness_rate']:.3f}")
    
    # Shutdown
    snit.shutdown()
