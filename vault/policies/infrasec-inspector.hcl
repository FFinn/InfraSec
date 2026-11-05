# Только сведения о конфигурации; значения KV недоступны.
path "sys/mounts" { capabilities = ["read"] }
path "sys/auth" { capabilities = ["read"] }
path "sys/audit" { capabilities = ["read", "sudo"] }
path "sys/storage/raft/configuration" { capabilities = ["read", "sudo"] }
path "sys/policies/acl/infrasec-frontend" { capabilities = ["read"] }
path "sys/policies/acl/infrasec-backend" { capabilities = ["read"] }
path "sys/policies/acl/infrasec-ci" { capabilities = ["read"] }
path "sys/policies/acl/infrasec-ansible" { capabilities = ["read"] }
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
