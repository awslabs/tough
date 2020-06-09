const toxy = require('toxy')
const poisons = toxy.poisons
const rules = toxy.rules

// Create a new toxy proxy
const proxy = toxy()
proxy
    .forward('http://172.12.13.3:5050')

// Register poisons and rules
proxy
    .get('/metadata/snapshot.json')
    .poison(poisons.abort({delay: 100}))
    .rule(rules.probability(50))

proxy
    .get('/metadata/targets.json')
    .poison(poisons.inject({
        code: 503,
        body: '{"error": "toxy injected error"}',
        headers: {'Content-Type': 'application/json'}
    }))
    .rule(rules.probability(50))

proxy
    .get('/*')

proxy.listen(3000)
console.log('Server listening on port:', 3000)
