# D3 raw independent-rating contingency table

This table is the pre-reconciliation evidence behind the mediated/unmediated
classification agreement reported in Section III-A. It compares the two raters' blind
classifications of the same 52 tools. Rows are the first rater; columns are the second.
It is not the reconciled classification used in `mediation.csv`.

| First rater \ Second rater | Partial | Unmediated | N/A | Row total |
| --- | ---: | ---: | ---: | ---: |
| Partial | 0 | 17 | 2 | 19 |
| Unmediated | 0 | 12 | 0 | 12 |
| N/A | 0 | 11 | 10 | 21 |
| Column total | 0 | 40 | 12 | 52 |

The observed agreement is 22/52 = 0.4231. Expected agreement from the marginal
distributions is 0.2707, giving Cohen's $\kappa = (0.4231 - 0.2707) / (1 - 0.2707) =
0.209$. The asymmetric use of `partial` (19 versus 0 assignments) is why this is treated
as exploratory coding under an under-specified scheme, not strong independent validation.
