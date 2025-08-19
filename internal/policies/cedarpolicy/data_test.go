package cedarpolicy_test

const (
	policy1 = "policy1.cedar"
	policy2 = "policy2.cedar"
)

var policies = map[string]string{
	policy1: `
		permit (
			principal == Subject::"me",
			action == Action::"GET",
			resource is Route
		) when { context.route == "my.service.com/mine" };
		permit (
			principal == Subject::"me",
			action == Action::"DELETE",
			resource is Route
		) when { context.route == "my.service.com/mine" };
	`,
	policy2: `
		permit (
			principal == Subject::"you",
			action == Action::"GET",
			resource is Route
		) when { context.route == "my.service.com/yours" };
		permit (
			principal == Subject::"you",
			action == Action::"DELETE",
			resource is Route
		) when { context.route == "my.service.com/yours" };
	`,
}
