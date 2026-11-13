// Step one of the deliberate disaster: destroy the tenant's data, and COMMIT.
//
// Split across two files on purpose. PocketBase runs each migration in its own
// transaction, so a single file that mutated and then threw would be rolled
// back by PocketBase itself — and the acceptance check would pass without ever
// exercising the pre_deploy snapshot. Deleting in a migration that succeeds
// makes the data loss real; the next migration is what stops the boot.
migrate((app) => {
    for (const record of app.findAllRecords("notes")) {
        app.delete(record);
    }
});
