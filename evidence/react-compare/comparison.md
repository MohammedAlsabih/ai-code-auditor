| file | ESLint verdict | prototype verdict | classification |
|---|---|---|---|
| arrow_component_ok.tsx | clean | clean | agree-clean |
| clean_component.tsx | clean | clean | agree-clean |
| custom_hook_ok.tsx | clean | clean | agree-clean |
| effect_deps_complete.tsx | clean | clean | agree-clean |
| effect_missing_dep.tsx | WARN exhaustive-deps L8 | R005 L6 | agree-flag[deps] |
| effect_no_deps.tsx | clean | R004 L5 | prototype-FP[deps] |
| effect_reads_setter.tsx | clean | clean | agree-clean |
| hook_after_early_return.tsx | ERROR rules-of-hooks L6 | clean | prototype-FN[placement] |
| hook_in_class_method.tsx | ERROR rules-of-hooks L7 | R003 L7 | agree-flag[placement] |
| hook_in_event_handler.tsx | ERROR rules-of-hooks L8 | clean | prototype-FN[placement] |
| hook_in_for.tsx | ERROR rules-of-hooks L7 | R001 L7 | agree-flag[placement] |
| hook_in_if.tsx | ERROR rules-of-hooks L6 | R001 L6 | agree-flag[placement] |
| hook_in_logical_and.tsx | ERROR rules-of-hooks L5 | clean | prototype-FN[placement] |
| hook_in_plain_function.tsx | ERROR rules-of-hooks L5 | R003 L5 | agree-flag[placement] |
| hook_in_ternary.tsx | ERROR rules-of-hooks L5 | R001 L5 | agree-flag[placement] |
| hook_in_try_catch.tsx | clean | R001 L6 | prototype-FP[placement] |
| hook_in_useeffect_cb.tsx | ERROR rules-of-hooks L6 | R005 L5; R002 L6 | agree-flag[placement] + prototype-FP[deps] |
| hook_in_usememo_cb.tsx | ERROR rules-of-hooks L6 | R002 L6 | agree-flag[placement] |

TOTALS: files=18  prototype-FP=3  prototype-FN=3
FP list: [('effect_no_deps.tsx', 'deps', ['R004']), ('hook_in_try_catch.tsx', 'placement', ['R001']), ('hook_in_useeffect_cb.tsx', 'deps', ['R005'])]
FN list: [('hook_after_early_return.tsx', 'placement', ['react-hooks/rules-of-hooks']), ('hook_in_event_handler.tsx', 'placement', ['react-hooks/rules-of-hooks']), ('hook_in_logical_and.tsx', 'placement', ['react-hooks/rules-of-hooks'])]