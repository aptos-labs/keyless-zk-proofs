# What is the change being pushed?

<!--
 Describe **what** the change is. e.g.,:
  - fixing a soundness bug in the IsLessThan() template
  - adding a new test for IsLessThan() to ensure that 3 < 3 cannot be satisfied
  - adding an new `/vk` endpoint to the prover service
-->

## Why are you pushing this change?

<!--
 Describe **why** you are making this change. Give as much context as needed,
 such as when/how a bug was found, why is it important that it be fixed, etc. 
 e.g.,:
  - IsLessThan() was underconstrained and wrongly allowed for 3 < 3. This would lead to a soundness break in higher level applications.
  - Important for our tests cover all edge cases.
  - We want to make it easy for anybody to see what VK the prover service is currently using.
-->

## How is this implemented?

<!--
 Describe **how** your change was implemented.
 The goal is to help reviewers and future readers understand this PR. e.g.,:
  - explain what well-known algorithms you are using, if any
  - explain the structure of the code
  - if modifying the circuit, explain why you expect your changes to maintain correctness and soundness 
  - identify any critical parts of the code that require special attention or understanding. Explain why these parts are crucial to the functionality or architecture of the project.
  - point out any areas where complex logic has been implemented. Provide a brief explanation of the logic and your approach to make it easier for reviewers to follow.
  - highlight any areas where you are particularly concerned or unsure about the code's impact on the change. This can include potential performance or security issues, or compatibility with existing features.
-->

# Type of change

<!-- 
Select one or more for each category, as applicable.
Delete the category, if not applicable.
Or, introduce your own, if needed.
-->

**Circuit change?**

- [ ] New circuit feature
- [ ] Circuit correctness fix
- [ ] Circuit soundness fix
- [ ] Circuit test cases
- [ ] Circuit benchmarks

**Prover service change?**

- [ ] New feature
- [ ] Bug fix
- [ ] Breaking change
- [ ] Performance improvement
- [ ] Refactoring
- [ ] Dependency update
- [ ] Documentation update
- [ ] Tests
- [ ] Benchmarks

# Checklist

- [ ] I have performed a self-review of my own code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I identified and added all keyless stakeholders and component owners affected by this change as reviewers
- [ ] I tested both happy and unhappy path of the functionality
- [ ] I have made corresponding changes to the documentation

<!-- Thank you for your contribution! -->
