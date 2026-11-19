# Access rules (self-test fixture)

Every route the app serves, and who may call it. The access test fails
when the app has a route this table doesn't list.

| Route | Who may call it |
|---|---|
| `GET /` | anyone |
| `GET /items/{item_id}` | anyone |
