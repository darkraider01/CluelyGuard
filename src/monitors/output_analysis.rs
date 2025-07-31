use std::collections::HashMap;
use regex::Regex;
use tracing::{info, warn, error};
use serde::{Serialize, Deserialize};
use crate::config::OutputAnalysisConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub is_suspicious: bool,
    pub confidence: f64,
    pub reasons: Vec<String>,
    pub scores: AnalysisScores,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisScores {
    pub perplexity: f64,
    pub burstiness: f64,
    pub pattern_matches: usize,
    pub stylistic_score: f64,
    pub keyword_density: f64,
}

impl Default for AnalysisScores {
    fn default() -> Self {
        Self {
            perplexity: 0.0,
            burstiness: 0.0,
            pattern_matches: 0,
            stylistic_score: 0.0,
            keyword_density: 0.0,
        }
    }
}

pub struct OutputAnalyzer {
    config: OutputAnalysisConfig,
    ai_patterns: Vec<Regex>,
}

impl OutputAnalyzer {
    pub fn new(config: OutputAnalysisConfig) -> Self {
        let ai_patterns = config.suspicious_phrases.iter()
            .filter_map(|p| Regex::new(&format!("(?i){}", regex::escape(p))).ok())
            .collect();
        OutputAnalyzer {
            config,
            ai_patterns,
        }
    }

    pub fn analyze_text(&self, text: &str) -> AnalysisResult {
        let mut scores = AnalysisScores::default();
        let mut reasons = Vec::new();

        // Perplexity analysis
        scores.perplexity = self.calculate_perplexity(text);
        if scores.perplexity < self.config.perplexity_threshold {
            reasons.push("Low perplexity detected (characteristic of AI text)".to_string());
        }

        // Burstiness analysis
        scores.burstiness = self.calculate_burstiness(text);
        if scores.burstiness < self.config.burstiness_threshold {
            reasons.push("Low burstiness detected (uniform sentence structure)".to_string());
        }

        // Pattern matching
        scores.pattern_matches = self.check_ai_patterns(text);
        if scores.pattern_matches > 0 {
            reasons.push(format!("Found {} AI-specific patterns", scores.pattern_matches));
        }

        // Stylistic analysis
        scores.stylistic_score = self.analyze_writing_style(text);
        if scores.stylistic_score > 0.6 {
            reasons.push("AI writing style patterns detected".to_string());
        }

        // Keyword density
        scores.keyword_density = self.calculate_keyword_density(text);
        if scores.keyword_density > self.config.keyword_threshold {
            reasons.push("High density of AI-related keywords".to_string());
        }

        let confidence = self.calculate_confidence(&scores);
        let is_suspicious = confidence > 0.5;

        AnalysisResult {
            is_suspicious,
            confidence,
            reasons,
            scores,
        }
    }

    fn calculate_perplexity(&self, text: &str) -> f64 {
        let words: Vec<&str> = text.split_whitespace().collect();
        if words.len() < 10 {
            return 1.0; // Not enough data
        }

        // Simple bigram perplexity calculation
        let mut bigram_counts: HashMap<String, usize> = HashMap::new();
        let mut word_counts: HashMap<&str, usize> = HashMap::new();

        for word in &words {
            *word_counts.entry(word).or_insert(0) += 1;
        }

        for window in words.windows(2) {
            let bigram = format!("{} {}", window[0], window[1]);
            *bigram_counts.entry(bigram).or_insert(0) += 1;
        }

        let mut log_prob_sum = 0.0;
        let mut count = 0;

        for window in words.windows(2) {
            let bigram = format!("{} {}", window[0], window[1]);
            let bigram_count = *bigram_counts.get(&bigram).unwrap_or(&0) as f64;
            let word_count = *word_counts.get(window[0]).unwrap_or(&0) as f64;
            
            if word_count > 0.0 {
                let prob = (bigram_count + 1.0) / (word_count + word_counts.len() as f64);
                log_prob_sum += prob.ln();
                count += 1;
            }
        }

        if count > 0 {
            (-log_prob_sum / count as f64).exp()
        } else {
            1.0
        }
    }

    fn calculate_burstiness(&self, text: &str) -> f64 {
        let sentences: Vec<&str> = text.split(&['.', '!', '?'][..]).collect();
        if sentences.len() < 3 {
            return 1.0;
        }

        let lengths: Vec<usize> = sentences
            .iter()
            .map(|s| s.trim().split_whitespace().count())
            .filter(|&len| len > 0)
            .collect();

        if lengths.len() < 2 {
            return 1.0;
        }

        let mean = lengths.iter().sum::<usize>() as f64 / lengths.len() as f64;
        let variance = lengths
            .iter()
            .map(|&len| (len as f64 - mean).powi(2))
            .sum::<f64>()
            / lengths.len() as f64;

        let std_dev = variance.sqrt();
        
        if mean > 0.0 {
            std_dev / mean // Coefficient of variation
        } else {
            0.0
        }
    }

    fn check_ai_patterns(&self, text: &str) -> usize {
        self.ai_patterns
            .iter()
            .map(|pattern| pattern.find_iter(text).count())
            .sum()
    }

    fn analyze_writing_style(&self, text: &str) -> f64 {
        let mut score = 0.0;
        
        // Check for overly formal language
        let formal_phrases = [
            "furthermore", "moreover", "additionally", "consequently",
            "therefore", "nevertheless", "however", "indeed"
        ];
        
        let word_count = text.split_whitespace().count() as f64;
        let formal_count = formal_phrases
            .iter()
            .map(|phrase| text.to_lowercase().matches(phrase).count())
            .sum::<usize>() as f64;
        
        if word_count > 0.0 {
            score += (formal_count / word_count) * 2.0;
        }

        // Check for consistent punctuation patterns
        let exclamation_count = text.matches('!').count() as f64;
        let question_count = text.matches('?').count() as f64;
        let period_count = text.matches('.').count() as f64;
        
        let total_sentences = exclamation_count + question_count + period_count;
        if total_sentences > 0.0 {
            let period_ratio = period_count / total_sentences;
            if period_ratio > 0.9 {
                score += 0.3; // Very consistent punctuation
            }
        }

        // Check for lack of contractions
        let contractions = ["don't", "can't", "won't", "I'm", "you're", "it's"];
        let contraction_count = contractions
            .iter()
            .map(|contr| text.to_lowercase().matches(contr).count())
            .sum::<usize>() as f64;
        
        if word_count > 50.0 && contraction_count / word_count < 0.01 {
            score += 0.2; // Very few contractions
        }

        score.min(1.0)
    }

    fn calculate_keyword_density(&self, text: &str) -> f64 {
        let word_count = text.split_whitespace().count() as f64;
        if word_count == 0.0 {
            return 0.0;
        }

        let keyword_count = self.config.suspicious_phrases
            .iter()
            .map(|phrase| text.to_lowercase().matches(&phrase.to_lowercase()).count())
            .sum::<usize>() as f64;

        keyword_count / word_count
    }

    fn calculate_confidence(&self, scores: &AnalysisScores) -> f64 {
        let mut confidence = 0.0;
        
        // Perplexity weight
        if scores.perplexity < self.config.perplexity_threshold {
            confidence += 0.25 * (self.config.perplexity_threshold - scores.perplexity) / self.config.perplexity_threshold;
        }
        
        // Burstiness weight
        if scores.burstiness < self.config.burstiness_threshold {
            confidence += 0.20 * (self.config.burstiness_threshold - scores.burstiness) / self.config.burstiness_threshold;
        }
        
        // Pattern matches weight
        confidence += 0.30 * (scores.pattern_matches as f64 / 5.0).min(1.0);
        
        // Stylistic score weight
        confidence += 0.15 * scores.stylistic_score;
        
        // Keyword density weight
        confidence += 0.10 * (scores.keyword_density / self.config.keyword_threshold).min(1.0);
        
        confidence.min(1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OutputAnalysisConfig;

    fn create_test_config() -> OutputAnalysisConfig {
        OutputAnalysisConfig {
            enabled: true,
            perplexity_threshold: 0.7,
            burstiness_threshold: 0.3,
            keyword_threshold: 0.15,
            suspicious_phrases: vec![
                "as an AI".to_string(),
                "language model".to_string(),
            ],
        }
    }

    #[test]
    fn test_ai_text_detection() {
        let config = create_test_config();
        let analyzer = OutputAnalyzer::new(config);
        
        let ai_text = "As an AI language model, I don't have personal experiences. However, I can provide information based on my training data.";
        let result = analyzer.analyze_text(ai_text);
        
        assert!(result.is_suspicious);
        assert!(result.confidence > 0.5);
        assert!(result.scores.pattern_matches > 0);
    }

    #[test]
    fn test_human_text_detection() {
        let config = create_test_config();
        let analyzer = OutputAnalyzer::new(config);
        
        let human_text = "Hey! I went to the store yesterday and it was crazy busy. The lines were so long, I almost gave up. But I really needed milk so I stuck it out.";
        let result = analyzer.analyze_text(human_text);
        
        assert!(!result.is_suspicious || result.confidence < 0.3);
    }
}
