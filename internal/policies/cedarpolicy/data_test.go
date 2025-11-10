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
			resource is Route
		) when {
			principal in [
				Subject::"me!t1",
				Subject::"me!t2"
			] &&
			context.type == "jwt" &&
			context.route like "*/my/stuff*" &&
			[
				"https://localhost:1234",
				"https://127.0.0.1:1234"
			].contains(context.issuer)
		};
		permit (
			principal,
			action == Action::"DELETE",
			resource is Route
		) when {
			principal in [
				Subject::"me!t1",
				Subject::"me!t2"
			] &&
			context.type == "jwt" &&
			context.route like "*/my/stuff*" &&
			[
				"https://localhost:1234",
				"https://127.0.0.1:1234"
			].contains(context.issuer)
		};
	`,
	policy2: `
		permit (
			principal,
			action == Action::"GET",
			resource is Route
		) when {
			principal in [
				Subject::"you!t1",
				Subject::"you!t2"
			] &&
			context.type == "jwt" &&
			context.route like "*/your/stuff*" &&
			[
				"https://localhost:1234",
				"https://127.0.0.1:1234"
			].contains(context.issuer)
		};
		permit (
			principal,
			action == Action::"DELETE",
			resource is Route
		) when {
			principal in [
				Subject::"you!t1",
				Subject::"you!t2"
			] &&
			context.type == "jwt" &&
			context.route like "*/your/stuff*" &&
			[
				"https://localhost:1234",
				"https://127.0.0.1:1234"
			].contains(context.issuer)
		};
	`,
}
