use anyhow::Result;
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusMode {
    Implicit,
    ExplicitDebate,
    ConfidenceWeighted,
}

impl Default for ConsensusMode {
    fn default() -> Self {
        Self::ConfidenceWeighted
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerspectiveResult {
    pub agent_id: Uuid,
    pub content: Vec<u8>,
    pub confidence: f64,
    pub metadata: HashMap<String, String>,
    pub timestamp: i64,
}

impl PerspectiveResult {
    pub fn new(agent_id: Uuid, content: Vec<u8>, confidence: f64) -> Self {
        Self {
            agent_id,
            content,
            confidence: confidence.clamp(0.0, 1.0),
            metadata: HashMap::new(),
            timestamp: chrono::Utc::now().timestamp(),
        }
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusInput {
    pub request_id: Uuid,
    pub topic: String,
    pub results: Vec<PerspectiveResult>,
    pub mode: ConsensusMode,
    pub threshold: f64,
}

impl ConsensusInput {
    pub fn new(request_id: Uuid, topic: String, mode: ConsensusMode) -> Self {
        Self {
            request_id,
            topic,
            results: Vec::new(),
            mode,
            threshold: 0.7,
        }
    }

    pub fn with_results(mut self, results: Vec<PerspectiveResult>) -> Self {
        self.results = results;
        self
    }

    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.threshold = threshold;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Disagreement {
    pub agent_ids: Vec<Uuid>,
    pub divergence_score: f64,
    pub conflicting_content: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusOutput {
    pub request_id: Uuid,
    pub agreed_content: Option<Vec<u8>>,
    pub confidence: f64,
    pub agreement_level: f64,
    pub mode_used: ConsensusMode,
    pub disagreements: Vec<Disagreement>,
    pub contributing_agents: Vec<Uuid>,
    pub processing_time_ms: u64,
}

impl ConsensusOutput {
    pub fn has_consensus(&self) -> bool {
        self.agreed_content.is_some() && self.agreement_level >= 0.5
    }
}

#[derive(Clone)]
pub struct ConsensusEngine {
    disagreement_threshold: f64,
    max_debate_rounds: u32,
}

impl ConsensusEngine {
    pub fn new() -> Self {
        Self {
            disagreement_threshold: 0.3,
            max_debate_rounds: 3,
        }
    }

    pub fn with_disagreement_threshold(mut self, threshold: f64) -> Self {
        self.disagreement_threshold = threshold;
        self
    }

    pub fn with_max_debate_rounds(mut self, rounds: u32) -> Self {
        self.max_debate_rounds = rounds;
        self
    }

    #[instrument(skip(self, input), fields(request_id = %input.request_id, results_count = %input.results.len(), mode = ?input.mode))]
    pub async fn reach_consensus(&self, input: ConsensusInput) -> Result<ConsensusOutput> {
        let start = std::time::Instant::now();
        
        if input.results.is_empty() {
            return Err(anyhow::anyhow!("No results to reach consensus on"));
        }

        let output = match input.mode {
            ConsensusMode::Implicit => self.implicit_consensus(input).await?,
            ConsensusMode::ExplicitDebate => self.explicit_debate(input).await?,
            ConsensusMode::ConfidenceWeighted => self.confidence_weighted(input).await?,
        };

        let elapsed = start.elapsed().as_millis() as u64;
        debug!(
            request_id = %output.request_id,
            consensus_reached = output.has_consensus(),
            agreement = output.agreement_level,
            time_ms = elapsed,
            "Consensus reached"
        );

        Ok(output)
    }

    async fn implicit_consensus(&self, input: ConsensusInput) -> Result<ConsensusOutput> {
        if input.results.len() == 1 {
            let result = &input.results[0];
            return Ok(ConsensusOutput {
                request_id: input.request_id,
                agreed_content: Some(result.content.clone()),
                confidence: result.confidence,
                agreement_level: 1.0,
                mode_used: ConsensusMode::Implicit,
                disagreements: Vec::new(),
                contributing_agents: vec![result.agent_id],
                processing_time_ms: 0,
            });
        }

        let content_similarity = self.calculate_content_similarity(&input.results);
        let agreement_level = content_similarity;
        
        let mut content_groups: HashMap<Vec<u8>, Vec<Uuid>> = HashMap::new();
        for result in &input.results {
            content_groups
                .entry(result.content.clone())
                .or_default()
                .push(result.agent_id);
        }

        let agreed_content = if agreement_level >= input.threshold {
            let largest_group = content_groups
                .iter()
                .max_by_key(|(_, agents)| agents.len())
                .map(|(content, _)| content.clone());
            largest_group
        } else {
            None
        };

        let disagreements = self.detect_disagreements(&input.results, content_similarity);

        let confidence = if let Some(ref content) = agreed_content {
            input
                .results
                .iter()
                .filter(|r| &r.content == content)
                .map(|r| r.confidence)
                .sum::<f64>()
                / input.results.len() as f64
        } else {
            0.0
        };

        Ok(ConsensusOutput {
            request_id: input.request_id,
            agreed_content,
            confidence,
            agreement_level,
            mode_used: ConsensusMode::Implicit,
            disagreements,
            contributing_agents: input.results.iter().map(|r| r.agent_id).collect(),
            processing_time_ms: 0,
        })
    }

    async fn explicit_debate(&self, input: ConsensusInput) -> Result<ConsensusOutput> {
        let mut results = input.results.clone();
        let mut all_disagreements = Vec::new();
        
        for round in 0..self.max_debate_rounds {
            debug!(round = round + 1, max_rounds = self.max_debate_rounds, "Debate round");
            
            let similarity = self.calculate_content_similarity(&results);
            
            if similarity >= input.threshold {
                break;
            }

            let disagreements = self.detect_disagreements(&results, similarity);
            all_disagreements.extend(disagreements);
            
            results = self.clarify_positions(results).await;
        }

        let final_similarity = self.calculate_content_similarity(&results);
        
        let mut content_groups: HashMap<Vec<u8>, Vec<Uuid>> = HashMap::new();
        for result in &results {
            content_groups
                .entry(result.content.clone())
                .or_default()
                .push(result.agent_id);
        }

        let agreed_content = content_groups
            .iter()
            .max_by_key(|(_, agents)| agents.len())
            .filter(|(_, agents)| agents.len() >= 2)
            .map(|(content, _)| content.clone());

        let agreement_level = if agreed_content.is_some() {
            let max_count = content_groups
                .iter()
                .map(|(_, agents)| agents.len())
                .max()
                .unwrap_or(0);
            max_count as f64 / results.len() as f64
        } else {
            0.0
        };

        let confidence = input
            .results
            .iter()
            .map(|r| r.confidence)
            .sum::<f64>()
            / input.results.len() as f64;

        Ok(ConsensusOutput {
            request_id: input.request_id,
            agreed_content,
            confidence,
            agreement_level,
            mode_used: ConsensusMode::ExplicitDebate,
            disagreements: all_disagreements,
            contributing_agents: input.results.iter().map(|r| r.agent_id).collect(),
            processing_time_ms: 0,
        })
    }

    async fn confidence_weighted(&self, input: ConsensusInput) -> Result<ConsensusOutput> {
        let total_weight: f64 = input.results.iter().map(|r| r.confidence).sum();
        
        if total_weight == 0.0 {
            return self.implicit_consensus(input).await;
        }

        let mut weighted_contents: HashMap<Vec<u8>, (f64, Vec<Uuid>)> = HashMap::new();
        
        for result in &input.results {
            let weight = result.confidence / total_weight;
            let entry = weighted_contents.entry(result.content.clone()).or_insert((0.0, Vec::new()));
            entry.0 += weight;
            entry.1.push(result.agent_id);
        }

        let best_content = weighted_contents
            .iter()
            .max_by(|a, b| {
                a.1 .0
                    .partial_cmp(&b.1 .0)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(content, (weight, agents))| {
                (content.clone(), *weight, agents.clone())
            });

        let (agreed_content, agreement_level, contributing_agents) = match best_content {
            Some((content, weight, agents)) if weight >= input.threshold => {
                (Some(content), weight, agents)
            }
            _ => {
                let largest = weighted_contents
                    .iter()
                    .max_by_key(|(_, (_, agents))| agents.len());
                
                match largest {
                    Some((content, (_, agents))) => (
                        Some(content.clone()),
                        agents.len() as f64 / input.results.len() as f64,
                        agents.clone(),
                    ),
                    None => (None, 0.0, Vec::new()),
                }
            }
        };

        let disagreements = self.detect_disagreements(&input.results, agreement_level);
        
        let confidence = input
            .results
            .iter()
            .map(|r| r.confidence)
            .sum::<f64>()
            / input.results.len() as f64;

        Ok(ConsensusOutput {
            request_id: input.request_id,
            agreed_content,
            confidence,
            agreement_level,
            mode_used: ConsensusMode::ConfidenceWeighted,
            disagreements,
            contributing_agents,
            processing_time_ms: 0,
        })
    }

    fn calculate_content_similarity(&self, results: &[PerspectiveResult]) -> f64 {
        if results.len() < 2 {
            return 1.0;
        }

        let mut total_similarity = 0.0;
        let mut comparisons = 0;

        for i in 0..results.len() {
            for j in (i + 1)..results.len() {
                let similarity = self.byte_similarity(&results[i].content, &results[j].content);
                total_similarity += similarity;
                comparisons += 1;
            }
        }

        if comparisons == 0 {
            return 1.0;
        }

        total_similarity / comparisons as f64
    }

    fn byte_similarity(&self, a: &[u8], b: &[u8]) -> f64 {
        if a.is_empty() && b.is_empty() {
            return 1.0;
        }
        if a.is_empty() || b.is_empty() {
            return 0.0;
        }

        let set_a: HashSet<_> = a.iter().collect();
        let set_b: HashSet<_> = b.iter().collect();
        
        let intersection = set_a.intersection(&set_b).count();
        let union = set_a.union(&set_b).count();
        
        if union == 0 {
            return 1.0;
        }

        intersection as f64 / union as f64
    }

    fn detect_disagreements(
        &self,
        results: &[PerspectiveResult],
        similarity: f64,
    ) -> Vec<Disagreement> {
        let mut disagreements = Vec::new();

        if similarity >= self.disagreement_threshold {
            return disagreements;
        }

        let mut content_groups: HashMap<Vec<u8>, Vec<Uuid>> = HashMap::new();
        for result in results {
            content_groups
                .entry(result.content.clone())
                .or_default()
                .push(result.agent_id);
        }

        if content_groups.len() > 1 {
            let groups: Vec<_> = content_groups.into_iter().collect();
            
            for i in 0..groups.len() {
                for j in (i + 1)..groups.len() {
                    let agent_ids: Vec<Uuid> = groups[i]
                        .1
                        .iter()
                        .chain(groups[j].1.iter())
                        .copied()
                        .collect();
                    
                    disagreements.push(Disagreement {
                        agent_ids,
                        divergence_score: 1.0 - similarity,
                        conflicting_content: vec![groups[i].0.clone(), groups[j].0.clone()],
                    });
                }
            }
        }

        disagreements
    }

    async fn clarify_positions(&self, results: Vec<PerspectiveResult>) -> Vec<PerspectiveResult> {
        results
            .into_iter()
            .map(|mut r| {
                r.confidence = (r.confidence * 0.8).clamp(0.1, 1.0);
                r
            })
            .collect()
    }
}

impl Default for ConsensusEngine {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ConsensusAggregator {
    engines: Arc<DashMap<Uuid, ConsensusEngine>>,
}

impl ConsensusAggregator {
    pub fn new() -> Self {
        Self {
            engines: Arc::new(DashMap::new()),
        }
    }

    pub async fn aggregate(
        &self,
        inputs: Vec<ConsensusInput>,
    ) -> Result<Vec<ConsensusOutput>> {
        let mut outputs = Vec::new();
        
        for input in inputs {
            let engine = ConsensusEngine::new();
            let output = engine.reach_consensus(input).await?;
            outputs.push(output);
        }
        
        Ok(outputs)
    }

    pub async fn aggregate_parallel(
        &self,
        inputs: Vec<ConsensusInput>,
    ) -> Result<Vec<ConsensusOutput>> {
        use futures::stream::{self, StreamExt};
        
        let engine = ConsensusEngine::new();
        
        let results: Vec<Result<ConsensusOutput, anyhow::Error>> = stream::iter(inputs)
            .map(|input| {
                let eng = ConsensusEngine::new();
                async move {
                    eng.reach_consensus(input).await
                }
            })
            .buffer_unordered(10)
            .collect()
            .await;
        
        let outputs: Vec<ConsensusOutput> = results
            .into_iter()
            .filter_map(|r| r.ok())
            .collect();
        
        Ok(outputs)
    }
}

impl Default for ConsensusAggregator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_implicit_consensus() {
        let engine = ConsensusEngine::new();
        
        let input = ConsensusInput::new(
            Uuid::new_v4(),
            "test topic".to_string(),
            ConsensusMode::Implicit,
        )
        .with_results(vec![
            PerspectiveResult::new(Uuid::new_v4(), b"answer 1".to_vec(), 0.8),
            PerspectiveResult::new(Uuid::new_v4(), b"answer 1".to_vec(), 0.9),
            PerspectiveResult::new(Uuid::new_v4(), b"answer 1".to_vec(), 0.7),
        ])
        .with_threshold(0.5);
        
        let output = engine.reach_consensus(input).await.unwrap();
        
        assert!(output.has_consensus());
        assert_eq!(output.agreement_level, 1.0);
    }

    #[tokio::test]
    async fn test_confidence_weighted() {
        let engine = ConsensusEngine::new();
        
        let input = ConsensusInput::new(
            Uuid::new_v4(),
            "test topic".to_string(),
            ConsensusMode::ConfidenceWeighted,
        )
        .with_results(vec![
            PerspectiveResult::new(Uuid::new_v4(), b"high confidence".to_vec(), 0.95),
            PerspectiveResult::new(Uuid::new_v4(), b"low confidence".to_vec(), 0.3),
            PerspectiveResult::new(Uuid::new_v4(), b"low confidence".to_vec(), 0.3),
        ])
        .with_threshold(0.5);
        
        let output = engine.reach_consensus(input).await.unwrap();
        
        assert!(output.has_consensus());
    }

    #[tokio::test]
    async fn test_disagreement_detection() {
        let engine = ConsensusEngine::new();
        
        let input = ConsensusInput::new(
            Uuid::new_v4(),
            "test topic".to_string(),
            ConsensusMode::Implicit,
        )
        .with_results(vec![
            PerspectiveResult::new(Uuid::new_v4(), b"answer A".to_vec(), 0.9),
            PerspectiveResult::new(Uuid::new_v4(), b"answer B".to_vec(), 0.8),
            PerspectiveResult::new(Uuid::new_v4(), b"answer C".to_vec(), 0.85),
        ])
        .with_threshold(0.9);
        
        let output = engine.reach_consensus(input).await.unwrap();
        
        assert!(!output.has_consensus());
        assert!(!output.disagreements.is_empty());
    }
}
