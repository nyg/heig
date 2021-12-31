const chance = require('chance').Chance()

const express = require('express')
const app = express()
const port = 3000

app.get('/', (req, res) => res.send(generateAddresses()))
app.listen(port, () => console.log('Express.js listening on port', port))

// Generates totally random addresses.
function generateAddresses() {

    const addressCount = chance.integer({ min: 1, max: 10 })
    const addresses = []

    for (var i = 0; i < addressCount; i++) {
        addresses.push({
            coordinates: chance.coordinates(),
            street: chance.address(),
            city: {
                name: chance.city(),
                zip: chance.zip()
            },
            province: chance.province({ full: true }),
            country: chance.country({ full: true })
        })
    }

    return addresses
}
