// The 0.22.x migration API: `new Dao(db)` and `saveCollection`, with a `schema`
// array rather than `fields`. Written for the OLD line on purpose — this
// package is a tenant who has not touched their project in a year.
//
// It never runs again after an upgrade: PocketBase records applied migrations,
// so a file that could not run on a newer binary is exactly the real situation
// and not a problem for the rehearsal.
migrate((db) => {
    const dao = new Dao(db);
    const collection = new Collection({
        name: "notes",
        type: "base",
        listRule: "",
        viewRule: "",
        createRule: "",
        updateRule: "",
        deleteRule: "",
        schema: [
            { name: "body", type: "text", required: false },
        ],
    });
    return dao.saveCollection(collection);
}, (db) => {
    const dao = new Dao(db);
    return dao.deleteCollection(dao.findCollectionByNameOrId("notes"));
});
