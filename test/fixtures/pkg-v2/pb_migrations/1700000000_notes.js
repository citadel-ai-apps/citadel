// Creates the collection the acceptance suite writes a record into before it
// deploys a deliberately broken package. That record surviving the rollback is
// what proves the pre_deploy snapshot works (design §8.5).
migrate((app) => {
    const notes = new Collection({
        type: "base",
        name: "notes",
        listRule: "",
        viewRule: "",
        createRule: "",
        updateRule: "",
        deleteRule: "",
        fields: [
            { name: "body", type: "text", required: false },
        ],
    });
    app.save(notes);
}, (app) => {
    app.delete(app.findCollectionByNameOrId("notes"));
});
