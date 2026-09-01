'use strict';

class TransferLedger {
  constructor() {
    this.nextId = 1000;
    this.transfers = [];
  }

  scheduleTransfer(request) {
    const transfer = {
      id: `tr_${this.nextId++}`,
      fromUserId: request.fromUserId,
      toAccount: request.toAccount,
      amountCents: request.amountCents,
      queuedAt: new Date().toISOString()
    };
    this.transfers.push(transfer);
    return transfer;
  }
}

module.exports = { TransferLedger };
