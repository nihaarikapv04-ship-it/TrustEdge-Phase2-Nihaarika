"""Phase 1 adaptive signature validation, persisted as per-device SQLite state.

Validation perturbs feature vectors in memory; it never generates live traffic.
Streaming moments replace an unbounded vector list while retaining the centroid
and population variance used by the reference validation formula.
"""
import numpy as np


def new_state():
    return dict(count=0, mean=[0.]*14, m2=[0.]*14, threshold=.7, milestone=0, complete=False)


def observe(state, features, score_fn):
    if state['complete']:
        return True
    count = state['count'] + 1
    mean = np.asarray(state['mean'])
    delta = np.asarray(features) - mean
    updated = mean + delta / count
    m2 = np.asarray(state['m2']) + delta * (np.asarray(features) - updated)
    state.update(count=count, mean=updated.tolist(), m2=m2.tolist())
    index = state['milestone']
    if count >= (10,20,30)[index]:
        std = np.sqrt(np.maximum(m2/count, 0)) + 1e-6
        passed = [score_fn(np.maximum(updated + scale*std, 0).tolist()) >= minimum
                  for scale, minimum in ((2., .20),(5., .45),(15., .70))]
        if all(passed):
            state['threshold'] = (.65,.55,.50)[index]
            state['milestone'] += 1
            state['complete'] = state['milestone'] == 3
    return state['complete']
