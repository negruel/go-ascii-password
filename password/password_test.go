/*

Copyright 2018 Brian Gollwitzer

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

File   : password_test.go
Package: password
Purpose: test suite for package

*/

package password

import (
	"testing"
)

type stats struct {
	length int
	upper  int
	lower  int
	number int
	symbol int
	other  int
}

func Test_validateArgs(t *testing.T) {
	type args struct {
		p Password
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"Negavitve MinLen", args{Password{MinLength: -1, Upper: 0, Lower: 0, Number: 0, Symbol: 0, ValidSymbols: nil}}, true},
		{"Negavitve Lower", args{Password{MinLength: 0, Upper: 0, Lower: -1, Number: 0, Symbol: 0, ValidSymbols: nil}}, true},
		{"Negavitve Number", args{Password{MinLength: 0, Upper: 0, Lower: 0, Number: -1, Symbol: 0, ValidSymbols: nil}}, true},
		{"Negavitve Symbol", args{Password{MinLength: 0, Upper: 0, Lower: 0, Number: 0, Symbol: -1, ValidSymbols: nil}}, true},
		{"Negavitve Upper", args{Password{MinLength: 0, Upper: -1, Lower: 0, Number: 0, Symbol: 0, ValidSymbols: nil}}, true},
		{"All Zero; Empty Validsymbols", args{Password{MinLength: 0, Upper: 0, Lower: 0, Number: 0, Symbol: 0, ValidSymbols: []rune{}}}, true},
		{"All Zero; nil Validsymbols", args{Password{MinLength: 0, Upper: 0, Lower: 0, Number: 0, Symbol: 0, ValidSymbols: nil}}, true},
		{"All Zero; Non-Empty Validsymbols", args{Password{MinLength: 0, Upper: 0, Lower: 0, Number: 0, Symbol: 0, ValidSymbols: []rune{65, 66, 67}}}, true},
		{"Empty Validsymbols", args{Password{MinLength: 10, Upper: 0, Lower: 0, Number: 0, Symbol: 5, ValidSymbols: []rune{}}}, true},
		{"nil Validsymbols", args{Password{MinLength: 10, Upper: 0, Lower: 0, Number: 0, Symbol: 5, ValidSymbols: nil}}, false},
		{"Non-Empty Validsymbols", args{Password{MinLength: 10, Upper: 0, Lower: 0, Number: 0, Symbol: 5, ValidSymbols: []rune{65, 66, 67}}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.args.p.validateArgs(); (err != nil) != tt.wantErr {
				t.Errorf("validateArgs() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
func TestPassword_Generate(t *testing.T) {
	type args struct {
		p Password
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"Upper1", args{Password{MinLength: 100, Upper: 1, Lower: 0, Number: 0, Symbol: 0, ValidSymbols: nil}}, false},
		{"Lower1", args{Password{MinLength: 100, Upper: 0, Lower: 1, Number: 0, Symbol: 0, ValidSymbols: nil}}, false},
		{"Number1", args{Password{MinLength: 100, Upper: 0, Lower: 0, Number: 1, Symbol: 0, ValidSymbols: nil}}, false},
		{"Symbol1a", args{Password{MinLength: 100, Upper: 0, Lower: 0, Number: 0, Symbol: 1, ValidSymbols: nil}}, false},
		{"Symbol1b", args{Password{MinLength: 100, Upper: 0, Lower: 0, Number: 0, Symbol: 1, ValidSymbols: []rune("!@#$%^&*()")}}, false},
		{"Upper2", args{Password{MinLength: 0, Upper: 1, Lower: 0, Number: 0, Symbol: 0, ValidSymbols: nil}}, false},
		{"Lower2", args{Password{MinLength: 0, Upper: 0, Lower: 1, Number: 0, Symbol: 0, ValidSymbols: nil}}, false},
		{"Number2", args{Password{MinLength: 0, Upper: 0, Lower: 0, Number: 1, Symbol: 0, ValidSymbols: nil}}, false},
		{"Symbol2", args{Password{MinLength: 0, Upper: 0, Lower: 0, Number: 0, Symbol: 1, ValidSymbols: nil}}, false},
		{"Symbol2", args{Password{MinLength: 0, Upper: 0, Lower: 0, Number: 0, Symbol: 1, ValidSymbols: []rune("!@#$%^&*()")}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPassword, err := tt.args.p.Generate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Password.Generate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			s := getPwdStats(&gotPassword, &tt.args.p)

			if s.length < tt.args.p.MinLength {
				t.Errorf("Password.Generate() error = password too short; password length: %d, want at least %d", s.length, tt.args.p.MinLength)
				return
			}

			if s.lower < tt.args.p.Lower {
				t.Errorf("Password.Generate() error = minimun # of lower case chars not met; lower required: %d, lower included %d", s.lower, tt.args.p.Lower)
				return
			}

			if s.upper < tt.args.p.Upper {
				t.Errorf("Password.Generate() error = minimun # of upper case chars not met; upper required: %d, upper included %d", s.upper, tt.args.p.Upper)
				return
			}

			if s.number < tt.args.p.Number {
				t.Errorf("Password.Generate() error = minimun # of numeric digits not met; number required: %d, number included %d", s.number, tt.args.p.Number)
				return
			}

			if s.symbol < tt.args.p.Symbol {
				t.Errorf("Password.Generate() error = minimun # of symbols not met; symbols required: %d, symbols included %d", s.symbol, tt.args.p.Symbol)
				return
			}
			if (tt.args.p.Lower == 0) && (s.lower > 0) {
				t.Errorf("Password.Generate() error = rule specified no lower case characters; %d found in password", s.lower)
				return
			}
			if (tt.args.p.Upper == 0) && (s.upper > 0) {
				t.Errorf("Password.Generate() error = rule specified no upper case characters; %d found in password", s.upper)
				return
			}
			if (tt.args.p.Number == 0) && (s.number > 0) {
				t.Errorf("Password.Generate() error = rule specified no numbers; %d found in password", s.number)
				return
			}
			if (tt.args.p.Symbol == 0) && (s.symbol > 0) {
				t.Errorf("Password.Generate() error = rule specified no special symbols; %d found in password", s.symbol)
				return
			}
			if s.other > 0 {
				t.Errorf("Password.Generate() error = unexpected symbols encountered; %d found in password", s.other)
				return
			}
		})
	}
}
func Benchmark_Generate001(b *testing.B) {
	type args struct {
		p Password
	}

	p := Password{MinLength: 16, Upper: 4, Lower: 4, Number: 4, Symbol: 4, ValidSymbols: []rune{}}

	for n := 0; n < b.N; n++ {
		_, err := p.Generate()
		if err != nil {
		}
	}

}
func Benchmark_Generate002(b *testing.B) {
	type args struct {
		p Password
	}

	p := Password{MinLength: 16, Upper: 1, Lower: 1, Number: 1, Symbol: 1, ValidSymbols: []rune{}}

	for n := 0; n < b.N; n++ {
		_, err := p.Generate()
		if err != nil {
		}
	}

}
func Benchmark_Generate003(b *testing.B) {
	type args struct {
		p Password
	}

	p := Password{MinLength: 32, Upper: 8, Lower: 8, Number: 8, Symbol: 8, ValidSymbols: []rune{}}

	for n := 0; n < b.N; n++ {
		_, err := p.Generate()
		if err != nil {
		}
	}

}
func Benchmark_Generate004(b *testing.B) {
	type args struct {
		p Password
	}

	r := Password{MinLength: 32, Upper: 1, Lower: 1, Number: 1, Symbol: 1, ValidSymbols: []rune{}}

	for n := 0; n < b.N; n++ {
		_, err := r.Generate()
		if err != nil {
		}
	}

}

// populates and returns stat struct with details of the password
// based on the defined rules
func getPwdStats(pwdStr *string, pwd *Password) stats {

	var upper, lower, symbol, number, other, length int
	var symbols []rune

	pwdSlice := []rune(*pwdStr)
	symbolMap := make(map[rune]int)

	if len(pwd.ValidSymbols) > 0 {
		symbols = []rune(pwd.ValidSymbols)
	} else {
		symbols = []rune(Symbols)
	}
	for i := 0; i < len(symbols); i++ {
		symbolMap[symbols[i]] = 1
	}

	length = len(pwdSlice)

	for i := 0; i < length; i++ {
		r := pwdSlice[i]
		if (r >= 48) && (r <= 57) { // 0-9
			number++
		} else if (r >= 65) && (r <= 90) { // A-Z
			upper++
		} else if (r >= 97) && (r <= 122) { // a-z
			lower++
		} else {
			_, fnd := symbolMap[r]
			if fnd {
				symbol++
			} else {
				other++
			}
		}
	}

	return stats{upper: upper, lower: lower, number: number, symbol: symbol, other: other, length: length}

}
