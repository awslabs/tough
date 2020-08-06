# Tuftool Examples

## Creating and Adding New Roles

The following example creates 2 roles, role1 and role2. role1 is a delegated targets of targets and role 2 is a delegated targets of role1.

### Create a new role named role1

`tuftool delegation --signing-role role1 create \`\
`--key path/to/role1/key \`\
`--expires in 2 days \`\
`--version 1 \`\
`--outdir role1/destination`\

### Add a new role named role1 to the targets role

`tuftool delegation --signing-role targets add-role \`\
`--delegated-role role1 \`\
`--key path/to/repo/owner/key \`\
`--paths foo?.txt \`\
`--expires in 2 days \`\
`--version 61 \`\
`--threshold 1 \`\
`--incoming-metadata role1/destination \`\
`--sign-all \`\
`--outdir metadata/with/role1 \`\
`--root path/to/root.json \`\
`--metadata-url path/to/metadata`

### Creating a role named role2

`tuftool delegation --signing-role role2 create \`\
`--key path/to/role2/key \`\
`--expires in 2 days \`\
`--version 1 \`\
`--outdir role2/destination`

### Add a new role named role2 to the role1 role

`tuftool delegation --signing-role role1 add-role \`\
`--delegated-role role2 \`\
`--key path/to/role1/key \`\
`--paths foo3.txt \`\
`--expires in 2 days \`\
`--version 1 \`\
`--threshold 1 \`\
`--incoming-metadata role2/destination \`\
`--sign-all \`\
`--outdir role1/and/role2/destination \`\
`--root path/to/root.json \`\
`--metadata-url metadata/with/role1`

### Updating role1 in the repository metadata

`tuftool update \`\
`--key path/to/repo/owner/key \`\
`--snapshot-version 73 \`\
`--snapshot-expires in 3 days \`\
`--targets-version 62 \`\
`--targets-expires in 7 days \`\
`--timestamp-version 592 \`\
`--timestamp-expires in 1 day \`\
`--role role1 \`\
`--incoming-metadata role1/and/role2/destination \`\
`--outdir metadata/with/role1/and/role2 \`\
`--root path/to/root.json \`\
`--metadata-url metadata/with/role1`

## Adding Keys to Delegated Roles

### Add a key to targets to sign role1

`tuftool delegation --signing-role targets add-key \`\
`--key path/to/repo/owner/key \`\
`--new-key path/to/new/role1/key \`\
`--expires in 2 days \`\
`--version 63 \`\
`--delegated-role role1 \`\
`--outdir targets/with/extra/role1/key \`\
`--root path/to/root.json \`\
`--metadata-url path/to/metadata`

### The repository needs to be updated with the new targets metadata

`tuftool update \`\
`--key path/to/repo/owner/key \`\
`--snapshot-version 74 \`\
`--snapshot-expires in 3 days \`\
`--targets-version 63 \`\
`--targets-expires in 7 days \`\
`--timestamp-version 593 \`\
`--timestamp-expires in 1 day \`\
`--role targets \`\
`--incoming-metadata targets/with/extra/role1/key \`\
`--outdir metadata/with/updated/role1/keys \`\
`--root path/to/root.json \`\
`--metadata-url path/to/metadata`

## Removing Keys from Delegated Roles

### Remove a key from targets for signing role1

`tuftool delegation --signing-role targets remove-key \`\
`--key path/to/repo/owner/key \`\
`--keyid keyid \`\
`--expires in 2 days \`\
`--version 63 \`\
`--delegated-role role1 \`\
`--outdir targets/with/removed/role1/key \`\
`--root path/to/root.json \`\
`--metadata-url path/to/metadata`

### The repository needs to be updated with the new targets metadata

`tuftool update \`\
`--key path/to/repo/owner/key \`\
`--snapshot-version 74 \`\
`--snapshot-expires in 3 days \`\
`--targets-version 63 \`\
`--targets-expires in 7 days \`\
`--timestamp-version 593 \`\
`--timestamp-expires in 1 day \`\
`--role targets \`\
`--incoming-metadata targets/with/removed/role1/key \`\
`--outdir metadata/with/updated/role1/keys \`\
`--root path/to/root.json \`\
`--metadata-url path/to/metadata`

## Removing a Role from a Delegated Role

### Remove role1 from targets

`tuftool delegation --signing-role targets add-key \`\
`--key path/to/repo/owner/key \`\
`--delegated-role role1 \`\
`--expires in 2 days \`\
`--version 63 \`\
`--outdir targets/with/removed/role1/key \`\
`--root path/to/root.json \`\
`--metadata-url path/to/metadata`

### The repository needs to be updated with the new targets metadata

`tuftool update \`\
`--key path/to/repo/owner/key \`\
`--snapshot-version 74 \`\
`--snapshot-expires in 3 days \`\
`--targets-version 63 \`\
`--targets-expires in 7 days \`\
`--timestamp-version 593 \`\
`--timestamp-expires in 1 day \`\
`--role targets \`\
`--incoming-metadata targets/with/removed/role1/key \`\
`--outdir metadata/with/updated/role1/keys \`\
`--root path/to/root.json \`\
`--metadata-url path/to/metadata`
