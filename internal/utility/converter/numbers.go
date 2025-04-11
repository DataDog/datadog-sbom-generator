package converter

import (
	"fmt"
	"math"
)

func SafeUIntToInt(number uint) (int, error) {
	if number > uint(math.MaxInt) {
		return 0, fmt.Errorf("uint value %d overflows int", number)
	}

	return int(number), nil
}
