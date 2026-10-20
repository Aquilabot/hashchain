package hashchain_test

import (
	"context"
	"errors"
	"fmt"

	"github.com/Aquilabot/hashchain"
)

func Example() {
	ctx := context.Background()
	chain, err := hashchain.New(hashchain.NewMemoryStore(), hashchain.Config{
		Key:  []byte("load-me-from-a-secret-store"), // optional: keyed (HMAC) chain
		Name: "billing-audit",
	})
	if err != nil {
		panic(err)
	}

	e, err := chain.Append(ctx, hashchain.Record{Kind: "invoice.paid", Payload: []byte(`{"invoice":"inv_1"}`)})
	if err != nil {
		panic(err)
	}
	fmt.Println("appended seq", e.Seq)

	report, err := chain.Verify(ctx)
	var broken *hashchain.VerifyError
	switch {
	case errors.As(err, &broken):
		fmt.Println("tampered at seq", broken.Seq, broken.Reason)
	case err != nil:
		panic(err)
	default:
		fmt.Println("verified", report.Entries, "entries; head seq", report.Last.Seq)
	}
	// Output:
	// appended seq 1
	// verified 2 entries; head seq 1
}
