// Step two: fail the boot, after the data is already gone.
//
// This is the most likely way a tenant bricks themselves (§8.5): tenant
// migrations run automatically at startup. The platform's answer is the
// pre_deploy snapshot and an automatic rollback, and this fixture is what
// proves it.
migrate((app) => {
    throw new Error("pkg-broken-migration: deliberate failure, after the notes were deleted");
});
