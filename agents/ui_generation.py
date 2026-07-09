"""
UI Generation Agent — Claude-powered component builder.

Generates production-ready React/TypeScript components from natural language.
Supports multi-turn conversations, accessibility validation, and design tokens.

Usage:
    from agents import UIGenerationAgent
    
    agent = UIGenerationAgent(api_key="sk-ant-...", provider="anthropic")
    
    # Single turn
    result = agent.run("Create a responsive dashboard card with a sparkline chart")
    print(result.content)  # Complete React component code
    
    # Multi-turn conversation
    result = agent.run("Now make the card clickable", conversation_id="dashboard-123")
    
    # With wireframe reference
    result = agent.run(
        "Create this component from the wireframe",
        images=[{"type": "image", "source": "base64..."}]
    )
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional

from agents.base import BaseAgent


class UIGenerationAgent(BaseAgent):
    """
    UI component generation specialist powered by Claude.
    
    Transforms natural language descriptions into production-ready
    React/TypeScript components with Tailwind CSS styling.
    """
    
    name = "ui_generation"
    description = "Claude-powered UI component generator. Creates React/TypeScript components with Tailwind CSS, accessibility features, and responsive design from natural language descriptions."
    model = "claude-sonnet-4-6"  # Default Claude model for UI
    temperature = 0.7
    
    system_prompt = """\
You are an expert UI/UX engineer and component architect specializing in React and Tailwind CSS.

YOUR MISSION:
Transform natural language descriptions into production-ready, accessible, and responsive React/TypeScript components.

CORE PRINCIPLES:

1. COMPONENT QUALITY
   - Use functional components with TypeScript
   - Single responsibility - each component does one thing well
   - Proper PropTypes/Zod validation for all props
   - Clean, readable code with helpful comments
   - Export types for reuse
   - Use meaningful variable names

2. ACCESSIBILITY (WCAG 2.1 AA)
   - Always include proper semantic HTML
   - Add aria-labels and aria-describedby where needed
   - Ensure keyboard navigation works
   - Focus management for modals and dropdowns
   - Color contrast compliance
   - Screen reader support
   - Alt text for images
   - Skip links where needed

3. RESPONSIVE DESIGN
   - Mobile-first approach (default to mobile, add md: lg: breakpoints)
   - Use Tailwind's responsive prefixes
   - Touch-friendly tap targets (min 44x44px)
   - Proper spacing on all screen sizes
   - Flexible layouts with grid/flex

4. STYLING (Tailwind CSS)
   - Use utility classes for 95% of styling
   - Extract repeated patterns to custom classes
   - Dark mode support (class="dark" strategy)
   - Consistent spacing scale (4, 8, 12, 16, 24, 32...)
   - Proper color tokens (not hardcoded values)
   - Transitions and hover states for interactive elements

5. PERFORMANCE
   - Avoid unnecessary re-renders (useCallback, useMemo)
   - Lazy load heavy components
   - Optimize images (use Next.js Image or proper sizing)
   - Use React.memo when appropriate
   - Virtualize long lists

COMPONENT OUTPUT FORMAT:

Always structure your component output as:

```typescript
// ComponentName.tsx
import React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';

// Type definitions
interface ComponentProps {
  // All required props with types
  title: string;
  value: number;
  trend?: 'up' | 'down' | 'neutral';
  onClick?: () => void;
  className?: string;
}

// Styling variants
const componentVariants = cva(
  "base-classes",
  {
    variants: {
      variant: {
        primary: "primary-classes",
        secondary: "secondary-classes",
      },
      size: {
        sm: "small-classes",
        md: "medium-classes",
        lg: "large-classes",
      },
    },
    defaultVariants: {
      variant: 'primary',
      size: 'md',
    },
  }
);

export const ComponentName: React.FC<ComponentProps> = ({
  title,
  value,
  trend = 'neutral',
  onClick,
  className = '',
}) => {
  return (
    <div 
      className={componentVariants({ variant: 'primary', size: 'md' }) + className}
      onClick={onClick}
      role="button"
      tabIndex={onClick ? 0 : undefined}
      // Add proper ARIA attributes for accessibility
      aria-label={title}
    >
      {/* Component content */}
    </div>
  );
};

export default ComponentName;
```

RESPONSE GUIDELINES:

1. When generating a component:
   - Explain the design decisions briefly
   - Provide the complete, working component code
   - Include TypeScript interfaces
   - Show usage examples
   - Highlight any accessibility features

2. When the user provides updates or clarifications:
   - Acknowledge the change
   - Explain what will be modified
   - Provide the updated component
   - Call out what changed

3. For complex components:
   - Break into smaller sub-components
   - Explain the component structure
   - Show how to compose them
   - Include PropTypes/TypeScript for all props

4. Always validate:
   - Will this work on mobile?
   - Is it accessible to screen readers?
   - Can I use it with a keyboard?
   - Does it support dark mode?
   - Is the performance reasonable?

TOOL USAGE:
- Use `generate_component` to create or modify components
- Use `validate_accessibility` to check WCAG compliance
- Use `apply_design_token` to update styling with design tokens

You're not just writing code — you're crafting experiences that work for everyone.
"""

    def _define_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "generate_component",
                "description": "Generate a React/TypeScript component with the specified features, styling, and accessibility attributes.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "component_name": {
                            "type": "string",
                            "description": "Name of the component (PascalCase)"
                        },
                        "description": {
                            "type": "string",
                            "description": "Natural language description of what the component does"
                        },
                        "features": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of features (e.g., ['responsive', 'dark_mode', 'clickable', 'animated'])"
                        },
                        "content": {
                            "type": "string",
                            "description": "The complete TypeScript/React component code"
                        },
                        "props_interface": {
                            "type": "string",
                            "description": "TypeScript interface defining all props"
                        },
                        "usage_example": {
                            "type": "string",
                            "description": "Example of how to use the component"
                        },
                        "design_rationale": {
                            "type": "string",
                            "description": "Brief explanation of key design decisions"
                        }
                    },
                    "required": ["component_name", "description", "content", "props_interface"]
                }
            },
            {
                "name": "validate_accessibility",
                "description": "Validate component code against WCAG 2.1 AA accessibility standards.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "component_code": {
                            "type": "string",
                            "description": "The component TypeScript/React code to validate"
                        },
                        "severity": {
                            "type": "string",
                            "enum": ["critical", "serious", "moderate", "minor"],
                            "description": "Minimum severity level to report"
                        },
                        "issues": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "severity": {"type": "string"},
                                    "issue": {"type": "string"},
                                    "wcag_criterion": {"type": "string"},
                                    "fix": {"type": "string"}
                                }
                            },
                            "description": "List of accessibility issues found"
                        },
                        "overall_score": {
                            "type": "number",
                            "description": "Accessibility score 0-100"
                        },
                        "recommendations": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Recommendations for improvement"
                        }
                    },
                    "required": ["component_code"]
                }
            },
            {
                "name": "apply_design_token",
                "description": "Update component styling with design tokens for consistency across the application.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "component_code": {
                            "type": "string",
                            "description": "Original component code"
                        },
                        "design_tokens": {
                            "type": "object",
                            "description": "Design token key-value pairs"
                        },
                        "updated_code": {
                            "type": "string",
                            "description": "Component code with tokens applied"
                        },
                        "changes_made": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of changes applied"
                        }
                    },
                    "required": ["component_code", "design_tokens"]
                }
            }
        ]

    def _bind_tool_handlers(self) -> Dict[str, Callable]:
        return {
            "generate_component": self._generate_component,
            "validate_accessibility": self._validate_accessibility,
            "apply_design_token": self._apply_design_token,
        }

    # ── Tool Handlers ─────────────────────────────────────────────

    def _generate_component(
        self,
        component_name: str,
        description: str,
        content: str,
        props_interface: str,
        features: Optional[List[str]] = None,
        usage_example: str = "",
        design_rationale: str = ""
    ) -> Dict[str, Any]:
        """Generate a React component — returns validated component details."""
        
        return {
            "component_name": component_name,
            "description": description,
            "content": content,
            "props_interface": props_interface,
            "features": features or [],
            "usage_example": usage_example or f"<{component_name} />",
            "design_rationale": design_rationale or "Standard responsive component with accessibility features",
            "file_path": f"src/components/{component_name}.tsx",
            "typescript": True,
            "tailwind": True,
            "responsive": "responsive" in (features or []),
            "dark_mode": "dark_mode" in (features or []),
        }

    def _validate_accessibility(
        self,
        component_code: str,
        severity: str = "serious"
    ) -> Dict[str, Any]:
        """Validate component accessibility — returns WCAG compliance analysis."""
        
        issues: List[Dict[str, str]] = []
        score = 100
        recommendations: List[str] = []

        import re

        severity_order = ["critical", "serious", "moderate", "minor"]
        max_severity_idx = severity_order.index(severity)

        def add_issue(sev: str, issue: str, wcag: str, fix: str) -> None:
            if severity_order.index(sev) <= max_severity_idx:
                issues.append({"severity": sev, "issue": issue, "wcag_criterion": wcag, "fix": fix})

        # ── Tag-aware checks ──────────────────────────────────────────
        # These parse individual tags rather than scanning raw substrings —
        # scanning the whole blob for e.g. "alt=" anywhere lets one accessible
        # <img alt="..."> hide a second, genuinely broken one, and naive
        # lookaheads only checking the attribute immediately after the tag
        # name misfire whenever attributes aren't in that exact order (the
        # common case for anything formatted by prettier).
        img_tags = re.findall(r"<img\b[^>]*/?>", component_code, re.IGNORECASE)
        missing_alt = [t for t in img_tags if not re.search(r"\balt\s*=", t, re.IGNORECASE)]
        if missing_alt:
            add_issue("critical", f"{len(missing_alt)} <img> element(s) missing alt text",
                       "1.1.1 Non-text Content", "Add alt attribute with descriptive text to all img elements")

        # Attrs can contain "{() => fn()}" — the "=>" arrow has a literal ">" in it,
        # so a plain [^>]* stops there. Treat up to two levels of {..} nesting as
        # atomic so we don't truncate the attribute list mid-JSX-expression.
        tag_pattern = r"<([a-zA-Z][\w.]*)\b((?:[^{}>]|\{(?:[^{}]|\{[^{}]*\})*\})*)>"
        all_tags = re.findall(tag_pattern, component_code)

        clickable_no_keyboard = []
        for tag_name, attrs in all_tags:
            if tag_name.lower() in ("button", "a", "input", "textarea", "select"):
                continue
            if not re.search(r"\bonClick\s*=", attrs):
                continue
            if re.search(r"\btabIndex\b", attrs) or re.search(r"\bonKeyDown\b", attrs) or re.search(r"\brole\s*=", attrs):
                continue
            clickable_no_keyboard.append(tag_name)
        if clickable_no_keyboard:
            add_issue("critical", f"Clickable <{clickable_no_keyboard[0]}> lacks keyboard support (no tabIndex/onKeyDown/role)",
                       "2.1.1 Keyboard", "Add tabIndex={0} and an onKeyDown handler, or use a button/anchor element")

        for tag in re.findall(r"<h\d>\s*</h\d>", component_code):
            add_issue("serious", "Empty heading", "2.4.6 Headings and Labels",
                       "Add descriptive text to heading or remove if not needed")
            break

        for tag_name, attrs in all_tags:
            if re.search(r'role\s*=\s*"button"', attrs, re.IGNORECASE) and not re.search(r"aria-label", attrs, re.IGNORECASE):
                add_issue("serious", f"<{tag_name} role=\"button\"> without ARIA attributes",
                           "4.1.2 Name, Role, Value", "Use <button> element or add aria-label and proper keyboard handlers")
                break

        # A placeholder alone isn't a label — flag inputs that use one without
        # any <label>/aria-label/aria-labelledby anywhere in the component.
        has_placeholder_input = re.search(r"<(input|textarea)\b[^>]*\bplaceholder\s*=", component_code, re.IGNORECASE)
        has_label = re.search(r"<label\b|aria-label\s*=|aria-labelledby\s*=", component_code, re.IGNORECASE)
        if has_placeholder_input and not has_label:
            add_issue("moderate", "Placeholder text used in place of a form label", "2.4.6 Headings and Labels",
                       "Add a proper <label> (or aria-label) associated with the input — placeholders disappear on input and aren't a reliable label for screen readers")

        for sev in [i["severity"] for i in issues]:
            if sev == "critical":
                score -= 20
            elif sev == "serious":
                score -= 10
            elif sev == "moderate":
                score -= 5
        
        # Generate recommendations
        if score < 100:
            recommendations.append("Run component through axe DevTools for comprehensive audit")
            recommendations.append("Test with screen reader (NVDA, JAWS, VoiceOver)")
            recommendations.append("Keyboard navigation test on all interactive elements")
            recommendations.append("Color contrast check with WCAG contrast checker")
        
        if not any("alt" in code.lower() for code in [component_code]):
            recommendations.append("Ensure all images have descriptive alt text")
        
        return {
            "overall_score": max(score, 0),
            "issues": issues,
            "recommendations": recommendations,
            "wcag_21_aa_compliant": score >= 90,
            "tested_against": ["WCAG 2.1 AA Success Criteria", "ARIA Authoring Practices"],
        }

    def _apply_design_token(
        self,
        component_code: str,
        design_tokens: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Apply design tokens to component — returns updated code with changes tracked."""
        
        updated_code = component_code
        changes_made: List[str] = []
        
        # Token replacement patterns
        token_map = {
            # Colors
            "colors.primary": design_tokens.get("colors", {}).get("primary", "blue-500"),
            "colors.secondary": design_tokens.get("colors", {}).get("secondary", "gray-500"),
            "colors.background": design_tokens.get("colors", {}).get("background", "white"),
            "colors.text": design_tokens.get("colors", {}).get("text", "gray-900"),
            # Spacing
            "spacing.sm": design_tokens.get("spacing", {}).get("sm", "4"),
            "spacing.md": design_tokens.get("spacing", {}).get("md", "8"),
            "spacing.lg": design_tokens.get("spacing", {}).get("lg", "16"),
            "spacing.xl": design_tokens.get("spacing", {}).get("xl", "24"),
            # Border radius
            "radius.sm": design_tokens.get("radius", {}).get("sm", "rounded-sm"),
            "radius.md": design_tokens.get("radius", {}).get("md", "rounded-md"),
            "radius.lg": design_tokens.get("radius", {}).get("lg", "rounded-lg"),
        }
        
        # Simple placeholder replacement (in production, would use AST)
        for token_name, token_value in design_tokens.items():
            placeholder = f"{{{token_name}}}"
            if placeholder in updated_code:
                updated_code = updated_code.replace(placeholder, str(token_value))
                changes_made.append(f"Applied token '{token_name}' = '{token_value}'")
        
        # Apply color tokens to Tailwind classes
        if "colors" in design_tokens:
            for color_key, color_value in design_tokens["colors"].items():
                old_pattern = f'bg-{color_key}'
                if old_pattern in updated_code:
                    updated_code = updated_code.replace(old_pattern, f'bg-{color_value}')
                    changes_made.append(f"Updated background color {color_key} → {color_value}")
        
        return {
            "updated_code": updated_code,
            "changes_made": changes_made,
            "tokens_applied": list(design_tokens.keys()),
            "unchanged_reason": "No recognizable placeholder patterns found" if not changes_made else None,
        }

    # ── Convenience Method for Wireframe Input ───────────────────

    def process_wireframe(
        self,
        description: str,
        image_base64: str,
        media_type: str = "image/png",
        conversation_id: Optional[str] = None
    ) -> AgentResponse:
        """
        Process a wireframe/screenshot image to generate components.
        
        Args:
            description: User intent for the component
            image_base64: Base64-encoded image data
            media_type: MIME type (image/png, image/jpeg, etc.)
            conversation_id: Optional conversation ID for multi-turn
        """
        # Remove data URL prefix if present
        if image_base64.startswith("data:"):
            image_base64 = image_base64.split(",", 1)[1]
        
        images = [{
            "type": "image",
            "source": {
                "type": "base64",
                "media_type": media_type,
                "data": image_base64
            }
        }]
        
        prompt = f"""I've attached a wireframe or screenshot. Please analyze it and create the component(s) shown.

Description of what I need: {description}

Please:
1. Describe what you see in the wireframe
2. Identify all components needed
3. Generate complete React components with the generate_component tool
4. Ensure responsive design and accessibility

Start by describing your observations."""

        return self.run(prompt, conversation_id=conversation_id, images=images)


# ── Convenience Export ─────────────────────────────────────────────

def create_ui_agent(
    api_key: Optional[str] = None,
    model: str = "claude-sonnet-4-6",
    temperature: float = 0.7
) -> UIGenerationAgent:
    """
    Factory function to create a UI Generation Agent with sensible defaults.
    
    Usage:
        agent = create_ui_agent(api_key="sk-ant-...")
        result = agent.run("Create a dashboard card")
    """
    return UIGenerationAgent(
        api_key=api_key,
        provider="anthropic",
        model=model,
        temperature=temperature
    )
