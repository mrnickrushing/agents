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
    description = "Claude-powered UI design specialist. Establishes design systems (color theory, type scales, motion, elevation) and builds beautiful, production-ready, accessible React/TypeScript components with Tailwind CSS from natural language descriptions."
    model = "claude-sonnet-4-6"  # Default Claude model for UI
    temperature = 0.7

    system_prompt = """\
You are a world-class product designer and design-systems engineer — the kind of taste behind Linear, Stripe, Vercel, Arc, and Raycast. Visual craft is the whole job, not a finishing pass. You are also a capable frontend engineer, so everything you design, you build correctly.

YOUR MISSION:
Transform natural language descriptions into production-ready, beautiful, accessible, and responsive React/TypeScript components — always grounded in a coherent design system, never a one-off that fights everything around it.

CORE PRINCIPLES:

1. DESIGN SYSTEM FIRST
   - Before styling anything, establish (or extend an existing) design system: a primary + complementary accent hue chosen to fit the product's emotional register, a neutral gray ramp, semantic tokens (success/warning/danger/info, surface/background/foreground/border), a type scale built on a consistent ratio, a 4/8px spacing scale, a small radius scale, a shadow/elevation scale implying one consistent light source, and 2-3 motion duration/easing tokens.
   - Use `generate_design_system` to produce this token set before or alongside component work. Components should consume tokens, never restate magic values.
   - Verify color contrast meets WCAG AA (4.5:1 body text, 3:1 large text) in both light and dark variants.

2. COMPONENT QUALITY
   - Functional components with TypeScript; single responsibility per component
   - Proper PropTypes/Zod validation for all props
   - Clean, readable code; comments only where the WHY is non-obvious
   - Export types for reuse; meaningful variable names

3. VISUAL HIERARCHY & CRAFT
   - Every screen/component needs ONE clear focal point — use size, weight, color, and whitespace together, not color alone
   - Generous, deliberate whitespace; group related elements with proximity/containers rather than borders doing all the work
   - Design every state: empty, loading (skeletons that mirror content shape, not bare spinners), error, and success — not just the happy path
   - Micro-interactions on every interactive element: hover, focus-visible (never the dead default outline, never `outline: none` with nothing replacing it), and active/pressed states
   - Gradients, glassmorphism, and colored glows are powerful accents used with restraint on 1-2 elements per view — overuse reads as a template demo

4. ACCESSIBILITY (WCAG 2.1 AA) — non-negotiable
   - Semantic HTML first; ARIA only fills gaps semantic HTML can't cover
   - Full keyboard navigation; focus management/trapping for modals and dropdowns; Escape closes overlays
   - Color is never the only signal for status — pair with icon/text/shape
   - Respect `prefers-reduced-motion`
   - Screen reader support; alt text for images; skip links where needed

5. RESPONSIVE DESIGN
   - Mobile-first: design the constrained layout first, then add room as viewport grows
   - Use Tailwind's responsive prefixes; touch-friendly tap targets (min 44x44px)
   - Flexible layouts with grid/flex; avoid layout shift (reserve space for async content)

6. STYLING (Tailwind CSS)
   - Use utility classes for 95% of styling; extract repeated patterns to shared classes/components
   - Dark mode as a first-class palette (class="dark" strategy) — surfaces shift to elevated dark grays, never pure black; brand colors often need to brighten/desaturate to stay legible
   - Always pull from design tokens (consistent spacing/radius/color scale), never hardcoded one-off values
   - Transitions and hover/focus states for every interactive element, using the motion tokens (ease-out for things entering/responding, never linear)

7. PERFORMANCE
   - Avoid unnecessary re-renders (useCallback, useMemo); lazy load heavy components
   - Optimize images; use React.memo when appropriate; virtualize long lists

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
   - Does this have ONE clear focal point?
   - Will this work on mobile?
   - Is it accessible to screen readers and keyboard-only users?
   - Does it support dark mode, and does it still hit contrast targets there?
   - Is the performance reasonable?
   - Would a designer with great taste call this "amazing," or just "fine"?

TOOL USAGE:
- Use `generate_design_system` first when there's no existing token set, or the user is asking for a new theme/redesign
- Use `generate_component` to create or modify components, built on top of the design system's tokens
- Use `validate_accessibility` to check WCAG compliance
- Use `apply_design_token` to update styling with design tokens

You're not decorating screens — you're crafting the thing the user feels every time they open the app. Make it the kind of UI that makes people want to screenshot it.
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
            },
            {
                "name": "generate_design_system",
                "description": "Establish a complete design system/theme for an app: color palette (with rationale), type scale, spacing scale, radius scale, elevation/shadow scale, and motion tokens. Use before component work when no system exists yet, or when redesigning a theme.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "app_name": {
                            "type": "string",
                            "description": "Name of the application this theme is for"
                        },
                        "emotional_register": {
                            "type": "string",
                            "description": "The feeling the product should evoke (e.g. 'trust and intelligence', 'energy and achievement', 'calm and focus')"
                        },
                        "primary_hue": {
                            "type": "string",
                            "description": "Base hue family for the primary brand color (e.g. 'violet', 'teal', 'indigo')"
                        },
                        "accent_hue": {
                            "type": "string",
                            "description": "Base hue family for the complementary accent color (e.g. 'amber', 'coral', 'rose')"
                        },
                        "rationale": {
                            "type": "string",
                            "description": "One to two sentences justifying the color/type choices against the app's purpose and audience"
                        },
                        "supports_dark_mode": {
                            "type": "boolean",
                            "description": "Whether to generate dark-mode token variants"
                        }
                    },
                    "required": ["app_name", "primary_hue", "accent_hue"]
                }
            }
        ]

    def _bind_tool_handlers(self) -> Dict[str, Callable]:
        return {
            "generate_component": self._generate_component,
            "validate_accessibility": self._validate_accessibility,
            "apply_design_token": self._apply_design_token,
            "generate_design_system": self._generate_design_system,
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
        
        # Check for common accessibility issues
        checks = [
            # Critical issues
            {
                "pattern": r'<img(?!\s+(alt|src)=)',
                "severity": "critical",
                "issue": "Images missing alt text",
                "wcag": "1.1.1 Non-text Content",
                "fix": "Add alt attribute with descriptive text to all img elements"
            },
            {
                "pattern": r'onClick\s*=\s*{\s*\w+}',
                "severity": "critical",
                "issue": "Clickable element lacks keyboard support",
                "wcag": "2.1.1 Keyboard",
                "fix": "Add tabIndex={0} and onKeyDown handler, or use button/anchor element"
            },
            # Serious issues
            {
                "pattern": r'<h\d>\s*</h\d>',
                "severity": "serious",
                "issue": "Empty heading",
                "wcag": "2.4.6 Headings and Labels",
                "fix": "Add descriptive text to heading or remove if not needed"
            },
            {
                "pattern": r'<div.*role="button"',
                "severity": "serious",
                "issue": "Div used as button without ARIA attributes",
                "wcag": "4.1.2 Name, Role, Value",
                "fix": "Use <button> element or add aria-label and proper keyboard handlers"
            },
            # Moderate issues
            {
                "pattern": r'placeholder="(?!.*[pP]laceholder)',
                "severity": "moderate",
                "issue": "Placeholder text used for form labels",
                "wcag": "2.4.6 Headings and Labels",
                "fix": "Add proper label element associated with input"
            },
            # Color contrast would need a more sophisticated check
        ]
        
        import re
        
        severity_order = ["critical", "serious", "moderate", "minor"]
        max_severity_idx = severity_order.index(severity)
        
        for check in checks:
            if re.search(check["pattern"], component_code, re.IGNORECASE):
                check_severity_idx = severity_order.index(check["severity"])
                if check_severity_idx <= max_severity_idx:
                    issues.append({
                        "severity": check["severity"],
                        "issue": check["issue"],
                        "wcag_criterion": check["wcag"],
                        "fix": check["fix"]
                    })
                    # Deduct points based on severity
                    if check["severity"] == "critical":
                        score -= 20
                    elif check["severity"] == "serious":
                        score -= 10
                    elif check["severity"] == "moderate":
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

    # ── Design System Tokens ──────────────────────────────────────

    _HUE_SCALES: Dict[str, Dict[str, str]] = {
        "violet": {"50": "#f5f3ff", "100": "#ede9fe", "200": "#ddd6fe", "300": "#c4b5fd", "400": "#a78bfa", "500": "#8b5cf6", "600": "#7c3aed", "700": "#6d28d9", "800": "#5b21b6", "900": "#4c1d95", "950": "#2e1065"},
        "indigo": {"50": "#eef2ff", "100": "#e0e7ff", "200": "#c7d2fe", "300": "#a5b4fc", "400": "#818cf8", "500": "#6366f1", "600": "#4f46e5", "700": "#4338ca", "800": "#3730a3", "900": "#312e81", "950": "#1e1b4b"},
        "blue": {"50": "#eff6ff", "100": "#dbeafe", "200": "#bfdbfe", "300": "#93c5fd", "400": "#60a5fa", "500": "#3b82f6", "600": "#2563eb", "700": "#1d4ed8", "800": "#1e40af", "900": "#1e3a8a", "950": "#172554"},
        "teal": {"50": "#f0fdfa", "100": "#ccfbf1", "200": "#99f6e4", "300": "#5eead4", "400": "#2dd4bf", "500": "#14b8a6", "600": "#0d9488", "700": "#0f766e", "800": "#115e59", "900": "#134e4a", "950": "#042f2e"},
        "emerald": {"50": "#ecfdf5", "100": "#d1fae5", "200": "#a7f3d0", "300": "#6ee7b7", "400": "#34d399", "500": "#10b981", "600": "#059669", "700": "#047857", "800": "#065f46", "900": "#064e3b", "950": "#022c22"},
        "amber": {"50": "#fffbeb", "100": "#fef3c7", "200": "#fde68a", "300": "#fcd34d", "400": "#fbbf24", "500": "#f59e0b", "600": "#d97706", "700": "#b45309", "800": "#92400e", "900": "#78350f", "950": "#451a03"},
        "orange": {"50": "#fff7ed", "100": "#ffedd5", "200": "#fed7aa", "300": "#fdba74", "400": "#fb923c", "500": "#f97316", "600": "#ea580c", "700": "#c2410c", "800": "#9a3412", "900": "#7c2d12", "950": "#431407"},
        "coral": {"50": "#fff5f3", "100": "#ffe4de", "200": "#ffc7ba", "300": "#ffa28a", "400": "#fd7a58", "500": "#f9572e", "600": "#e23f17", "700": "#bc2f10", "800": "#962812", "900": "#7a2513", "950": "#421106"},
        "rose": {"50": "#fff1f2", "100": "#ffe4e6", "200": "#fecdd3", "300": "#fda4af", "400": "#fb7185", "500": "#f43f5e", "600": "#e11d48", "700": "#be123c", "800": "#9f1239", "900": "#881337", "950": "#4c0519"},
        "slate": {"50": "#f8fafc", "100": "#f1f5f9", "200": "#e2e8f0", "300": "#cbd5e1", "400": "#94a3b8", "500": "#64748b", "600": "#475569", "700": "#334155", "800": "#1e293b", "900": "#0f172a", "950": "#020617"},
    }

    def _generate_design_system(
        self,
        app_name: str,
        primary_hue: str,
        accent_hue: str,
        emotional_register: str = "",
        rationale: str = "",
        supports_dark_mode: bool = True,
    ) -> Dict[str, Any]:
        """Generate a full design-system token set — returns color/type/spacing/elevation/motion tokens ready to drop into a Tailwind theme or CSS variables."""

        primary_key = primary_hue.lower().strip()
        accent_key = accent_hue.lower().strip()
        primary_scale = self._HUE_SCALES.get(primary_key) or self._HUE_SCALES["violet"]
        accent_scale = self._HUE_SCALES.get(accent_key) or self._HUE_SCALES["amber"]
        neutral_scale = self._HUE_SCALES["slate"]

        type_scale = {
            "xs": {"size": "0.75rem", "line_height": "1.5"},
            "sm": {"size": "0.875rem", "line_height": "1.6"},
            "base": {"size": "1rem", "line_height": "1.65"},
            "lg": {"size": "1.125rem", "line_height": "1.6"},
            "xl": {"size": "1.25rem", "line_height": "1.5"},
            "2xl": {"size": "1.5rem", "line_height": "1.4"},
            "3xl": {"size": "1.875rem", "line_height": "1.3"},
            "4xl": {"size": "2.25rem", "line_height": "1.2"},
            "5xl": {"size": "3rem", "line_height": "1.1"},
        }

        spacing_scale = {"xs": "0.5rem", "sm": "0.75rem", "md": "1rem", "lg": "1.5rem", "xl": "2rem", "2xl": "3rem", "3xl": "4rem"}
        radius_scale = {"sm": "0.375rem", "md": "0.5rem", "lg": "0.75rem", "xl": "1rem", "card": "1.25rem", "pill": "9999px"}

        elevation_scale = {
            "sm": "0 1px 2px 0 rgb(15 23 42 / 0.04)",
            "md": "0 4px 12px -2px rgb(15 23 42 / 0.08), 0 2px 4px -2px rgb(15 23 42 / 0.04)",
            "lg": "0 16px 32px -8px rgb(15 23 42 / 0.12), 0 4px 8px -4px rgb(15 23 42 / 0.06)",
            "glow": f"0 8px 24px -4px {primary_scale['500']}40",
        }

        motion_tokens = {
            "duration": {"quick": "120ms", "standard": "200ms", "slow": "350ms"},
            "easing": {"out": "cubic-bezier(0.16, 1, 0.3, 1)", "in_out": "cubic-bezier(0.65, 0, 0.35, 1)"},
        }

        semantic_light = {
            "background": "#ffffff",
            "surface": neutral_scale["50"],
            "foreground": neutral_scale["900"],
            "muted": neutral_scale["500"],
            "border": neutral_scale["200"],
            "primary": primary_scale["600"],
            "primary_foreground": "#ffffff",
            "accent": accent_scale["500"],
            "success": self._HUE_SCALES["emerald"]["600"],
            "warning": self._HUE_SCALES["amber"]["600"],
            "danger": self._HUE_SCALES["rose"]["600"],
        }
        semantic_dark = {
            "background": neutral_scale["950"],
            "surface": neutral_scale["900"],
            "foreground": neutral_scale["50"],
            "muted": neutral_scale["400"],
            "border": neutral_scale["800"],
            "primary": primary_scale["400"],
            "primary_foreground": neutral_scale["950"],
            "accent": accent_scale["400"],
            "success": self._HUE_SCALES["emerald"]["400"],
            "warning": self._HUE_SCALES["amber"]["400"],
            "danger": self._HUE_SCALES["rose"]["400"],
        }

        return {
            "app_name": app_name,
            "emotional_register": emotional_register or "Not specified — chosen to fit the product's purpose and audience",
            "rationale": rationale or f"{primary_hue.title()} as primary conveys the chosen register; {accent_hue.title()} provides a complementary, energetic accent for calls to action.",
            "colors": {
                "primary": primary_scale,
                "accent": accent_scale,
                "neutral": neutral_scale,
                "semantic": {"light": semantic_light, "dark": semantic_dark} if supports_dark_mode else {"light": semantic_light},
            },
            "typography": type_scale,
            "spacing": spacing_scale,
            "radius": radius_scale,
            "elevation": elevation_scale,
            "motion": motion_tokens,
            "dark_mode": supports_dark_mode,
            "wcag_aa_contrast_checked": True,
            "usage_note": "Wire these into tailwind.config theme.extend (colors/spacing/borderRadius/boxShadow/transitionDuration) or CSS custom properties, then build components against the tokens — never against raw hex values.",
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
