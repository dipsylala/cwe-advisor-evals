const express = require('express');
const app = express();

// In-memory store of support tickets, keyed by id.
const tickets = {
    'T-1001': { subject: 'Printer will not turn on', status: 'Open' }
};

app.get('/tickets/:id/confirmation', (req, res) => {
    const ticket = tickets[req.params.id];
    if (!ticket) {
        return res.status(404).send('Ticket not found');
    }

    // Agents can append a short note when closing a ticket; it arrives as a
    // query parameter from the "close ticket" form and is never persisted.
    const closingNote = req.query.note || '';

    const page = `
        <html>
            <body>
                <h1>Ticket ${req.params.id} - ${ticket.subject}</h1>
                <p>Status: ${ticket.status}</p>
                <p>Agent note: ${closingNote}</p>
            </body>
        </html>
    `;

    // SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
    res.send(page);
});

module.exports = app;
