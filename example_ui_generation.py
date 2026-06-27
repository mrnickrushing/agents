"""
UI Generation Agent — Complete Example

Demonstrates Claude-powered UI component generation with:
- Single-turn component generation
- Multi-turn conversation
- Wireframe/screenshot analysis
- Accessibility validation
- Design token application
"""

import os
from agents import UIGenerationAgent

# ============================================================================
# SETUP
# ============================================================================

# Set your Anthropic API key
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "sk-ant-test...")

# Initialize the agent (uses Claude by default)
agent = UIGenerationAgent(
    api_key=ANTHROPIC_API_KEY,
    provider="anthropic",
    model="claude-sonnet-4-6",
    temperature=0.7
)

print("=" * 60)
print("UI GENERATION AGENT - CLAUDE POWERED")
print("=" * 60)
print()

# ============================================================================
# EXAMPLE 1: Single-Turn Component Generation
# ============================================================================

print("EXAMPLE 1: Generate a Dashboard Card Component")
print("-" * 60)

response = agent.run(
    "Create a responsive dashboard card component with:"
    "- A title (string prop)"
    "- A metric value (number prop)"
    "- A trend indicator ('up', 'down', or 'neutral')"
    "- A mini sparkline chart shown as a visual indicator"
    "- Dark theme support"
    "- Clickable with hover effects"
    "- Fully accessible (keyboard navigation, screen reader support)"
)

print(response.content)
print("\nModel used:", response.model)
print("Tokens used:", response.usage)
print()

# ============================================================================
# EXAMPLE 2: Multi-Turn Conversation
# ============================================================================

print("\nEXAMPLE 2: Multi-Turn Conversation")
print("-" * 60)

# First turn - initial component
print("\nUser: Create a user profile card with avatar, name, and bio")
conversation_id = "profile-card-dev"

response1 = agent.run(
    "Create a user profile card component with:"
    "- Avatar image (src prop, alt text required)"
    "- User name (string prop)"
    "- Short bio text (string prop, 2 lines max)"
    "- Social media links (optional array of objects)"
    "- Make it responsive and accessible",
    conversation_id=conversation_id
)

print("\nAgent - First Response:")
print(response1.content[:500] + "...")  # Truncated for brevity

# Second turn - modification
print("\n\nUser: Now add a 'Follow' button with loading state ability")
response2 = agent.run(
    "Add a 'Follow' button that:"
    "- Shows 'Follow' when not following"
    "- Shows 'Following' when following"
    "- Shows a loading spinner when waiting for API response"
    "- Use proper button element and keyboard navigation",
    conversation_id=conversation_id
)

print("\nAgent - Second Response:")
print(response2.content[:500] + "...")

# Third turn - further refinement
print("\n\nUser: Add a link to view full profile")
response3 = agent.run(
    "Add a 'View Full Profile' link button that:"
    "- Uses an anchor element for proper semantics"
    "- Opens in new tab when external domain"
    "- Has appropriate ARIA attributes",
    conversation_id=conversation_id
)

print("\nAgent - Third Response:")
print(response3.content[:500] + "...")

print("\n\nConversation History:")
print(f"Total messages in conversation: {len(agent.history)}")
print()

# ============================================================================
# EXAMPLE 3: Wireframe/Screenshot Analysis
# ============================================================================

print("\nEXAMPLE 3: Wireframe to Component")
print("-" * 60)

# Note: This requires a real image - showing the pattern
print("Pattern for wireframe-to-component:")

example_code = '''
# If you have a base64-encoded wireframe:
import base64

# Read image file
with open("wireframe.png", "rb") as f:
    image_base64 = base64.b64encode(f.read()).decode()

# Process wireframe
response = agent.process_wireframe(
    description="Create a navigation bar component",
    image_base64=image_base64,
    media_type="image/png",
    conversation_id="navbar-dev"
)

print("Analysis from wireframe:", response.content)
'''

print(example_code)

# ============================================================================
# EXAMPLE 4: Accessibility Validation
# ============================================================================

print("\nEXAMPLE 4: Accessibility Validation")
print("-" * 60)

# Sample component with accessibility issues
problematic_component = """
import React from 'react';

export const BadCard = ({ title, value, onClick }) => {
  return (
    <div onClick={onClick}>
      <img src="icon.png" />
      <h4>{title}</h4>
      <div>{value}</div>
    </div>
  );
};
"""

print("\nComponent to validate:")
print(problematic_component)

# Trigger validation through a natural language request
validation_response = agent.run(
    f"Please validate this component for accessibility issues "
    f"against WCAG 2.1 AA standards:\n\n{problematic_component}"
)

print("\nAgent Validation Response:")
print(validation_response.content)

# ============================================================================
# EXAMPLE 5: Design Token Application
# ============================================================================

print("\nEXAMPLE 5: Apply Design Tokens")
print("-" * 60)

design_tokens_request = '''
I have a component with hardcoded colors. Please apply these design tokens:
- Primary color: indigo-600
- Secondary color: slate-600
- Background: dark theme (slate-900)
- Text: slate-100
- Spacing: use 8px scale (spacing-8)
- Radius: medium rounded (rounded-lg)

Make sure to update the component to use these tokens consistently.
'''

response = agent.run(design_tokens_request)
print("Design Token Update Response:")
print(response.content)

# ============================================================================
# EXAMPLE 6: Complex Multi-Component Page
# ============================================================================

print("\nEXAMPLE 6: Generate Multiple Related Components")
print("-" * 60)

complex_request = '''
I need to build a Settings page with these components:

1. SettingsLayout - Wraps page with sidebar navigation and main content area
2. SettingsSection - Groups related settings with collapsible header
3. ToggleSwitch - An accessible on/off toggle with proper form attributes
4. SelectInput - A dropdown select with label and error message support

All components should:
- Support dark mode
- Be fully accessible
- Use consistent spacing and colors
- Have TypeScript interfaces
- Include usage examples in comments

Please generate each component and explain how they work together.
'''

response = agent.run(complex_request)
print("\nMulti-Component Page Response:")
print(response.content[:800] + "...")
print("\n\nModel used:", response.model)
print("Tokens:", response.usage)

# ============================================================================
# SUMMARY
# ============================================================================

print("\n" + "=" * 60)
print("SUMMARY")
print("=" * 60)
print("""
The UI Generation Agent demonstrates:

1. Single-turn component generation from natural language
2. Multi-turn conversations with context retention
3. Wireframe/screenshot analysis for visual component creation
4. Built-in accessibility validation (WCAG 2.1 AA)
5. Design token application for consistent styling
6. Complex multi-component page generation

Key Features:
- Claude-powered for superior UI reasoning
- Full TypeScript support
- Tailwind CSS integration
- Responsive design (mobile-first)
- Accessibility-first approach
- Multi-turn conversation support
- Vision input for wireframes

Usage Patterns:
- Simple: agent.run("Create a component...")
- Conversational: agent.run("Add feature...", conversation_id="...")
- Visual: agent.process_wireframe("From this image...", image_data, ...)

The agent maintains conversation history per conversation_id,
allowing iterative refinement of components.
""")

print("\nReset conversation demo:")
agent.reset(conversation_id="profile-card-dev")
print(f"Conversation history after reset: {len(agent.history)} messages")