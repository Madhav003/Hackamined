from analyzer_engine import create_analyzer, analyze_text
from context_rules import apply_context_rules

analyzer = create_analyzer()
text = 'Finance confirmed that quarterly billing reconciliation has been completed.'
results = analyze_text(analyzer, text)
print("=== Before context rules ===")
for r in results:
    print(f'{r.entity_type:20s} score={r.score:.2f} [{r.start}:{r.end}] -> "{text[r.start:r.end]}"')

filtered = apply_context_rules(text, results)
print("\n=== After context rules ===")
for r in filtered:
    print(f'{r.entity_type:20s} score={r.score:.2f} [{r.start}:{r.end}] -> "{text[r.start:r.end]}"')
