# AGENTS.md

## Project Overview
This project is a smart network scanner that detects open ports and services on a target system and uses an AI model to explain potential security risks and recommended fixes in a clear, human-readable format. The goal is to transform raw network scan data into actionable security insights.

---

## Agent Role
The AI agent acts as a development assistant that helps design, implement, debug, and refine the system. It is responsible for generating code, improving structure, and suggesting enhancements while following project requirements and constraints.

---

## Development Loop (Agentic Workflow)
The project will be built using an iterative agentic loop:

1. **Plan**  
   The agent is prompted with a specific feature or goal (e.g., implement port scanning, add API endpoint, generate AI explanations).

2. **Generate**  
   The agent produces code or implementation steps.

3. **Execute**  
   The code is run locally to test functionality.

4. **Evaluate**  
   Outputs are reviewed, including:
   - Runtime errors
   - Scan results
   - Correctness of detected services
   - Quality of AI-generated explanations

5. **Refine**  
   Feedback is provided to the agent, such as:
   - Fix errors or crashes
   - Improve performance or readability
   - Adjust logic for more accurate detection
   - Improve clarity and relevance of explanations

6. **Repeat**  
   The loop continues until the feature meets expectations.

---

## Feedback Mechanisms

The agent will be guided using the following feedback signals:

### 1. Functional Testing
- Run scans on known targets (e.g., `localhost`)
- Verify detected ports and services match expected results

### 2. Error Handling
- Provide stack traces and error messages back to the agent
- Request fixes and improvements

### 3. Output Validation
- Ensure scan results are structured and accurate
- Confirm AI explanations:
  - Correctly describe the service
  - Identify realistic risks
  - Provide useful mitigation steps

### 3. Code Quality Review
- Ask the agent to:
  - Refactor for clarity and modularity
  - Add comments and documentation
  - Simplify overly complex logic

---

## Quality Metrics

The project will be evaluated using the following measurable metrics:

- **Service Detection Accuracy (%)**  
  Percentage of correctly identified services compared to known expected results.

- **Risk Classification Accuracy (%)**  
  How often the assigned risk level matches realistic security expectations.

- **Explanation Relevance Score**  
  Whether AI-generated explanations:
  - Match the detected service
  - Include accurate risks
  - Provide actionable recommendations

Improving these metrics corresponds directly to a more reliable and useful system.

---

## Constraints and Guidelines

- Keep the system simple and focused on core functionality
- Prioritize correctness and clarity over complexity
- Avoid overengineering the frontend; focus on backend and analysis
- Use AI to enhance understanding, not replace core logic

---

## Expected Outcome

By the end of the project, the system should:
- Successfully scan a target and detect open ports/services
- Clearly present results
- Generate accurate, helpful AI explanations of security risks
- Demonstrate a complete and effective agent-driven development process