# Get email of user on github.com
----
### ONE

https://docs.github.com/en/graphql/overview/explorer
```
{
  repository(name: "REPOSITORY_NAME", owner: "USER_NAME") {
    ref(qualifiedName: "master") {
      target {
        ... on Commit {
          id
          history(first: 5) {
            edges {
              node {
                author {
                  name
                  email
                }
              }
            }
          }
        }
      }
    }
  }
}

```

### TWO
```
https://api.github.com/users/<USER_NAME>/events/public
```

### THREE
```
https://github.com/USER_NAME/REPOSITORY_NAME/commit/24767922f7739a940014fd443dab9f334984ed02.patch
```
