module my-library

go 1.21.3

replace github.com/kubernetes/apimachinery => ../../../../../../random-folder

replace github.com/cenkalti/backoff/v4 v4.3.0 => github.com/Private/packages/pkg/util/backoff v1.0.0
