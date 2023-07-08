name: Issue
description: Report a bug or unexpected behavior. 🙏

body:
  - type: markdown
    attributes:
      value:  Thank you for contributing to Uvicorn! ✊

  - type: checkboxes
    id: checks
    attributes:
      label: Initial Checks
      description: Just making sure you open a discussion first. 🙏
      options:
        - label: I confirm this was discussed, and the maintainers suggest I open an issue.
          required: true
        - label: I'm aware that if I created this issue without a discussion, it may be closed without a response.
          required: true

  - type: textarea
    id: discussion
    attributes:
      label: Discussion Link
      description: |
        Please link to the discussion that led to this issue.

        If you haven't discussed this issue yet, please do so before opening an issue.
      render: Text
    validations:
      required: true

  - type: textarea
    id: description
    attributes:
      label: Description
      description: |
        Please explain what you're seeing and what you would expect to see.

        Please provide as much detail as possible to make understanding and solving your problem as quick as possible. 🙏
    validations:
      required: true

  - type: textarea
    id: example
    attributes:
      label: Example Code
      description: |
        If applicable, please add a self-contained,
        [minimal, reproducible, example](https://stackoverflow.com/help/minimal-reproducible-example)
        demonstrating the bug.

      placeholder: |
        import pydantic

        ...
      render: Python

  - type: textarea
    id: version
    attributes:
      label: Python, Uvicorn & OS Version
      description: |
        Which version of Python & Uvicorn are you using, and which Operating System?

        Please run the following command and copy the output below:

        ```bash
        python -m uvicorn --version
        ```

      render: Text
    validations:
      required: true
