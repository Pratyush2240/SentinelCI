$env:GITHUB_EVENT_PATH = "test_fixtures/fake_pr_event.json"
$env:GITHUB_SHA = "0ce651a"
# PR_BASE_SHA must be a commit SHA, not a branch name, to match what main.py now expects
$env:PR_BASE_SHA = "6de007e"

python -m app.main
