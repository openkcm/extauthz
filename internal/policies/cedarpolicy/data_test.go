package cedarpolicy_test

const (
	policy1 = "policy1.cedar"
	policy2 = "policy2.cedar"
)

var policies = map[string]string{
	policy1: `
		permit (
			principal,
			action == Action::"GET",
			resource
		) when {
			context.type == "jwt" &&
			context.path like "/my/stuff*" &&
			(
				(
					principal == Subject::"me!t1" &&
					context.issuer == "https://127.0.0.1:1234"
				) || (
					principal == Subject::"me!t2" &&
					context.issuer == "https://127.0.0.1:1234"
				)
			)
		};
		permit (
			principal,
			action == Action::"DELETE",
			resource
		) when {
			context.type == "jwt" &&
			context.path like "/my/stuff*" &&
			(
				(
					principal == Subject::"me!t1" &&
					context.issuer == "https://127.0.0.1:1234"
				) || (
					principal == Subject::"me!t2" &&
					context.issuer == "https://127.0.0.1:1234"
				)
			)
		};
	`,
	policy2: `
		permit (
			principal,
			action == Action::"GET",
			resource
		) when {
			context.type == "jwt" &&
			context.path like "/your/stuff*" &&
			(
				(
					principal == Subject::"you!t1" &&
					context.issuer == "https://127.0.0.1:1234"
				) || (
					principal == Subject::"you!t2" &&
					context.issuer == "https://127.0.0.1:1234"
				)
			)
		};
		permit (
			principal,
			action == Action::"DELETE",
			resource
		) when {
			context.type == "jwt" &&
			context.path like "/your/stuff*" &&
			(
				(
					principal == Subject::"you!t1" &&
					context.issuer == "https://127.0.0.1:1234"
				) || (
					principal == Subject::"you!t2" &&
					context.issuer == "https://127.0.0.1:1234"
				)
			)
		};
	`,
}
