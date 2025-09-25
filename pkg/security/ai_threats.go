package security

import (
	"context"
	"regexp"
	"strings"
	"time"

	"observeguard/internal/models"
)

// AIThreatDetector handles advanced AI-specific threat detection
type AIThreatDetector struct {
	promptInjectionPatterns []*regexp.Regexp
	jailbreakPatterns      []*regexp.Regexp
	bannedLLMPatterns      []*regexp.Regexp
	aiHackingToolPatterns  []*regexp.Regexp
	suspiciousCommands     []string
}

// NewAIThreatDetector creates a new AI threat detector
func NewAIThreatDetector() *AIThreatDetector {
	detector := &AIThreatDetector{}
	detector.initializePatterns()
	return detector
}

// initializePatterns initializes all threat detection patterns
func (d *AIThreatDetector) initializePatterns() {
	// Prompt Injection Patterns
	d.promptInjectionPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)ignore\s+previous\s+instructions`),
		regexp.MustCompile(`(?i)forget\s+(everything|all)\s+(above|before)`),
		regexp.MustCompile(`(?i)system\s*:\s*you\s+are\s+now`),
		regexp.MustCompile(`(?i)act\s+as\s+if\s+you\s+are`),
		regexp.MustCompile(`(?i)pretend\s+to\s+be`),
		regexp.MustCompile(`(?i)role\s*:\s*evil\s+assistant`),
		regexp.MustCompile(`(?i)jailbreak\s+mode`),
		regexp.MustCompile(`(?i)developer\s+mode\s+enabled`),
		regexp.MustCompile(`(?i)ignore\s+safety\s+guidelines`),
		regexp.MustCompile(`(?i)bypass\s+content\s+policy`),
		regexp.MustCompile(`(?i){{.*system.*}}`),
		regexp.MustCompile(`(?i)<\|im_start\|>system`),
		regexp.MustCompile(`(?i)\[SYSTEM\].*\[/SYSTEM\]`),
		regexp.MustCompile(`(?i)%%%\s*system\s*prompt`),
		regexp.MustCompile(`(?i)base64.*decode.*system`),
		regexp.MustCompile(`(?i)rot13.*system\s+prompt`),
	}

	// Jailbreak Patterns - sophisticated techniques
	d.jailbreakPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)dan\s+(mode|jailbreak)`),
		regexp.MustCompile(`(?i)do\s+anything\s+now`),
		regexp.MustCompile(`(?i)aim\s+jailbreak`),
		regexp.MustCompile(`(?i)evil\s+confidant`),
		regexp.MustCompile(`(?i)kevin\s+jailbreak`),
		regexp.MustCompile(`(?i)stan\s+jailbreak`),
		regexp.MustCompile(`(?i)dude\s+jailbreak`),
		regexp.MustCompile(`(?i)mongo\s+tom\s+jailbreak`),
		regexp.MustCompile(`(?i)hypothetical\s+response`),
		regexp.MustCompile(`(?i)in\s+a\s+fictional\s+world`),
		regexp.MustCompile(`(?i)alternate\s+reality\s+where`),
		regexp.MustCompile(`(?i)simulation\s+mode\s+activated`),
		regexp.MustCompile(`(?i)unrestricted\s+ai`),
		regexp.MustCompile(`(?i)sudo\s+mode`),
		regexp.MustCompile(`(?i)admin\s+override`),
		regexp.MustCompile(`(?i)god\s+mode\s+enabled`),
		regexp.MustCompile(`(?i)maximum\s+model`),
		regexp.MustCompile(`(?i)unfiltered\s+response`),
		regexp.MustCompile(`(?i)uncensored\s+mode`),
		regexp.MustCompile(`(?i)\{\{\s*evil\s*\}\}`),
		regexp.MustCompile(`(?i)opposite\s+day`),
		regexp.MustCompile(`(?i)reverse\s+psychology`),
		regexp.MustCompile(`(?i)hypothetically\s+speaking`),
	}

	// Banned LLM Detection Patterns
	d.bannedLLMPatterns = []*regexp.Regexp{
		// API endpoints of banned or monitored LLMs
		regexp.MustCompile(`api\.openai\.com`),
		regexp.MustCompile(`api\.anthropic\.com`),
		regexp.MustCompile(`generativelanguage\.googleapis\.com`),
		regexp.MustCompile(`api\.cohere\.ai`),
		regexp.MustCompile(`api\.huggingface\.co`),
		regexp.MustCompile(`api\.replicate\.com`),
		regexp.MustCompile(`api\.together\.xyz`),
		regexp.MustCompile(`api\.mistral\.ai`),
		regexp.MustCompile(`api\.groq\.com`),
		regexp.MustCompile(`api\.deepseek\.com`),
		regexp.MustCompile(`api\.perplexity\.ai`),
		regexp.MustCompile(`claude\.ai`),
		regexp.MustCompile(`chat\.openai\.com`),
		regexp.MustCompile(`bard\.google\.com`),
		regexp.MustCompile(`character\.ai`),
		regexp.MustCompile(`poe\.com`),
		regexp.MustCompile(`chatsonic\.writesonic\.com`),
		// Local LLM servers
		regexp.MustCompile(`localhost:(11434|8080|7860|5000)`), // Ollama, common local LLM ports
		regexp.MustCompile(`127\.0\.0\.1:(11434|8080|7860|5000)`),
		// Underground/Black market LLM services
		regexp.MustCompile(`(?i)uncensored.*llm`),
		regexp.MustCompile(`(?i)jailbroken.*ai`),
		regexp.MustCompile(`(?i)unrestricted.*gpt`),
	}

	// AI Hacking Tool Detection
	d.aiHackingToolPatterns = []*regexp.Regexp{
		// Known AI hacking tools
		regexp.MustCompile(`(?i)gpt.*red.*team`),
		regexp.MustCompile(`(?i)prompt.*injection.*tool`),
		regexp.MustCompile(`(?i)ai.*exploit.*kit`),
		regexp.MustCompile(`(?i)llm.*fuzzer`),
		regexp.MustCompile(`(?i)chatgpt.*jailbreak`),
		regexp.MustCompile(`(?i)claude.*exploit`),
		regexp.MustCompile(`(?i)bard.*hack`),
		regexp.MustCompile(`(?i)ai.*adversarial.*tool`),
		regexp.MustCompile(`(?i)prompt.*engineer.*attack`),
		regexp.MustCompile(`(?i)llm.*vulnerability.*scanner`),
		regexp.MustCompile(`(?i)ai.*security.*bypass`),
		regexp.MustCompile(`(?i)neural.*network.*backdoor`),
		regexp.MustCompile(`(?i)model.*poisoning.*tool`),
		regexp.MustCompile(`(?i)generative.*ai.*hack`),
	}

	// Suspicious CLI commands for AI hacking
	d.suspiciousCommands = []string{
		"curl -X POST.*api.openai.com.*jailbreak",
		"python.*prompt_injection.py",
		"python.*llm_exploit.py",
		"python.*ai_redteam.py",
		"python.*jailbreak_test.py",
		"node.*gpt-jailbreak",
		"python.*-c.*ignore previous instructions",
		"curl.*anthropic.*bypass",
		"wget.*jailbreak.*payload",
		"python.*adversarial_prompt.py",
		"ollama.*run.*uncensored",
		"docker.*run.*llm.*jailbreak",
		"python.*fuzzing.*llm",
		"python.*prompt.*attack",
		"python.*ai.*exploit",
		"python.*model.*extraction",
		"python.*backdoor.*injection",
		"python.*neural.*trojan",
	}
}

// DetectPromptInjection analyzes text for prompt injection attempts
func (d *AIThreatDetector) DetectPromptInjection(ctx context.Context, text string) *models.ThreatEvent {
	for i, pattern := range d.promptInjectionPatterns {
		if pattern.MatchString(text) {
			return &models.ThreatEvent{
				Event: models.Event{
					Type:      models.EventTypeThreat,
					Timestamp: time.Now(),
				},
				ThreatID:    "prompt_injection_" + string(rune(i)),
				Severity:    "high",
				Category:    "prompt_injection",
				Title:       "Prompt Injection Detected",
				Description: "Suspicious prompt injection pattern detected: " + pattern.String(),
				Indicators:  []string{pattern.String()},
				Status:      "active",
				Source:      "ai_threat_detector",
			}
		}
	}
	return nil
}

// DetectJailbreakAttempt analyzes text for jailbreak attempts
func (d *AIThreatDetector) DetectJailbreakAttempt(ctx context.Context, text string) *models.ThreatEvent {
	for i, pattern := range d.jailbreakPatterns {
		if pattern.MatchString(text) {
			return &models.ThreatEvent{
				Event: models.Event{
					Type:      models.EventTypeThreat,
					Timestamp: time.Now(),
				},
				ThreatID:    "jailbreak_attempt_" + string(rune(i)),
				Severity:    "critical",
				Category:    "jailbreak_attempt",
				Title:       "AI Jailbreak Attempt Detected",
				Description: "AI jailbreak attempt detected: " + pattern.String(),
				Indicators:  []string{pattern.String()},
				Status:      "active",
				Source:      "ai_threat_detector",
			}
		}
	}
	return nil
}

// DetectBannedLLMUsage analyzes network traffic for banned LLM usage
func (d *AIThreatDetector) DetectBannedLLMUsage(ctx context.Context, networkEvent *models.NetworkEvent) *models.ThreatEvent {
	// Check remote address against banned LLM patterns
	targetAddr := networkEvent.RemoteAddr
	for i, pattern := range d.bannedLLMPatterns {
		if pattern.MatchString(targetAddr) {
			severity := "high"
			if strings.Contains(targetAddr, "openai.com") || strings.Contains(targetAddr, "anthropic.com") {
				severity = "critical"
			}

			return &models.ThreatEvent{
				Event: models.Event{
					Type:      models.EventTypeThreat,
					Timestamp: time.Now(),
					PID:       networkEvent.PID,
					Process:   networkEvent.Process,
				},
				ThreatID:    "banned_llm_usage_" + string(rune(i)),
				Severity:    severity,
				Category:    "banned_llm_usage",
				Title:       "Banned LLM Service Access Detected",
				Description: "Process attempted to connect to banned LLM service: " + targetAddr,
				Indicators:  []string{targetAddr, networkEvent.Process},
				Status:      "active",
				Source:      "ai_threat_detector",
			}
		}
	}
	return nil
}

// DetectAIHackingTools analyzes process events for AI hacking tools
func (d *AIThreatDetector) DetectAIHackingTools(ctx context.Context, processEvent *models.ProcessEvent) *models.ThreatEvent {
	// Check command line arguments
	fullCommand := strings.Join(append([]string{processEvent.Command}, processEvent.Args...), " ")

	// Check against AI hacking tool patterns
	for i, pattern := range d.aiHackingToolPatterns {
		if pattern.MatchString(fullCommand) {
			return &models.ThreatEvent{
				Event: models.Event{
					Type:      models.EventTypeThreat,
					Timestamp: time.Now(),
					PID:       processEvent.PID,
					Process:   processEvent.Process,
				},
				ThreatID:    "ai_hacking_tool_" + string(rune(i)),
				Severity:    "critical",
				Category:    "ai_hacking_tool",
				Title:       "AI Hacking Tool Detected",
				Description: "AI hacking tool execution detected: " + fullCommand,
				Indicators:  []string{fullCommand, processEvent.Process},
				Status:      "active",
				Source:      "ai_threat_detector",
			}
		}
	}

	// Check against suspicious commands
	for _, suspiciousCmd := range d.suspiciousCommands {
		matched, _ := regexp.MatchString(suspiciousCmd, fullCommand)
		if matched {
			return &models.ThreatEvent{
				Event: models.Event{
					Type:      models.EventTypeThreat,
					Timestamp: time.Now(),
					PID:       processEvent.PID,
					Process:   processEvent.Process,
				},
				ThreatID:    "suspicious_ai_command",
				Severity:    "high",
				Category:    "ai_hacking_command",
				Title:       "Suspicious AI Hacking Command",
				Description: "Suspicious AI hacking command detected: " + fullCommand,
				Indicators:  []string{fullCommand},
				Status:      "active",
				Source:      "ai_threat_detector",
			}
		}
	}

	return nil
}

// DetectModelTheft analyzes file access patterns for potential model theft
func (d *AIThreatDetector) DetectModelTheft(ctx context.Context, fileEvent *models.FileEvent) *models.ThreatEvent {
	// Check for model file extensions
	modelExtensions := []string{".pt", ".pth", ".pb", ".onnx", ".h5", ".pkl", ".joblib", ".bin", ".safetensors"}
	isModelFile := false
	for _, ext := range modelExtensions {
		if strings.HasSuffix(strings.ToLower(fileEvent.Path), ext) {
			isModelFile = true
			break
		}
	}

	if !isModelFile {
		return nil
	}

	// Check if accessing process is suspicious
	suspiciousProcesses := []string{"curl", "wget", "scp", "rsync", "nc", "netcat", "python", "node"}
	isSuspiciousProcess := false
	for _, proc := range suspiciousProcesses {
		if strings.Contains(strings.ToLower(fileEvent.Process), proc) {
			isSuspiciousProcess = true
			break
		}
	}

	// Large file reads are suspicious
	isLargeRead := fileEvent.BytesRead > 50*1024*1024 // 50MB

	if isSuspiciousProcess && (fileEvent.Action == "read" || fileEvent.Action == "open") && isLargeRead {
		return &models.ThreatEvent{
			Event: models.Event{
				Type:      models.EventTypeThreat,
				Timestamp: time.Now(),
				PID:       fileEvent.PID,
				Process:   fileEvent.Process,
			},
			ThreatID:    "model_theft_attempt",
			Severity:    "critical",
			Category:    "model_theft",
			Title:       "AI Model Theft Attempt",
			Description: "Potential AI model theft detected: " + fileEvent.Path,
			Indicators:  []string{fileEvent.Path, fileEvent.Process},
			Status:      "active",
			Source:      "ai_threat_detector",
		}
	}

	return nil
}

// DetectAdversarialAttack analyzes patterns for adversarial attacks
func (d *AIThreatDetector) DetectAdversarialAttack(ctx context.Context, text string) *models.ThreatEvent {
	// Detect adversarial prompt patterns
	adversarialPatterns := []string{
		"repeat the word",
		"say the following exactly",
		"output raw text",
		"print verbatim",
		"echo this back",
		"copy paste this",
		"reproduce exactly",
		"mirror these words",
	}

	textLower := strings.ToLower(text)
	for _, pattern := range adversarialPatterns {
		if strings.Contains(textLower, pattern) {
			// Check if it's combined with other suspicious elements
			if strings.Contains(textLower, "system") ||
			   strings.Contains(textLower, "prompt") ||
			   strings.Contains(textLower, "ignore") {
				return &models.ThreatEvent{
					Event: models.Event{
						Type:      models.EventTypeThreat,
						Timestamp: time.Now(),
					},
					ThreatID:    "adversarial_attack",
					Severity:    "high",
					Category:    "adversarial_attack",
					Title:       "Adversarial Attack Detected",
					Description: "Adversarial attack pattern detected: " + pattern,
					Indicators:  []string{pattern},
					Status:      "active",
					Source:      "ai_threat_detector",
				}
			}
		}
	}

	return nil
}

// AnalyzeAIThreat performs comprehensive AI threat analysis
func (d *AIThreatDetector) AnalyzeAIThreat(ctx context.Context, event interface{}) *models.ThreatEvent {
	switch e := event.(type) {
	case *models.ProcessEvent:
		return d.DetectAIHackingTools(ctx, e)
	case *models.NetworkEvent:
		return d.DetectBannedLLMUsage(ctx, e)
	case *models.FileEvent:
		return d.DetectModelTheft(ctx, e)
	case string:
		// Analyze text for prompt injection and jailbreak attempts
		if threat := d.DetectPromptInjection(ctx, e); threat != nil {
			return threat
		}
		if threat := d.DetectJailbreakAttempt(ctx, e); threat != nil {
			return threat
		}
		return d.DetectAdversarialAttack(ctx, e)
	}

	return nil
}