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

File   : password.go
Package: password
Purpose: generates passwords using ascii characters that meet user-specified complexity rules

*/

package password

import (
	crytporand "crypto/rand"
	"errors"
	"math/big"
	"math/rand"
	"reflect"
	"time"
)

// Password provides methods to generate passwords comprised of
// ascii characters based on user-defined complexity rules
// MinLength - minimum length of the generated password
// Upper - minimum number of upper case characters; zero (0) if no upper case characters should be present.
// Lower - minimum number of lower case characters; zero (0) if no lower case characters should be present.
// Number - minimum number of numeric digits; zero (0) if no numeric digits should be present.
// Symbol - minimum number of special characters; zero (0) if no special characters should be used.
// ValidSymbols - rune slice of valid special characters; nil to use the default list defined by password.Symbols
type Password struct {
	MinLength    int
	Upper        int
	Lower        int
	Number       int
	Symbol       int
	ValidSymbols []rune
}

// UpperCaseLetters defines list of upper case letters to draw from
const UpperCaseLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

// LowerCaseLetters defines list of lower case letters to draw from
const LowerCaseLetters = "abcdefghijklmnopqrstuvwxyz"

// Numbers defines list of numeric digits to draw from
const Numbers = "0123456789"

// Symbols defines list of special symbols to draw from
const Symbols = "!@#$%^&*()-_=+[{]}|;:',\\<.>/?\""

func init() {

	// password makes use of the rand library. set the seed to generate
	// random passwords from the same rules.
	rand.Seed(time.Now().UTC().UnixNano())

}

func (p *Password) validateArgs() error {

	if p.MinLength < 0 {
		return errors.New("MinLength must be greater than or equal to zero (0)")
	}

	if p.Lower < 0 {
		return errors.New("MinLowerCase must be greater than or equal to zero (0)")
	}

	if p.Number < 0 {
		return errors.New("MinNumber must be greater than or equal to zero (0)")
	}

	if p.Symbol < 0 {
		return errors.New("MinSymbol must be greater than or equal to zero (0)")
	}

	if p.Upper < 0 {
		return errors.New("MinUpperCase must be greater than or equal to zero (0)")
	}

	if (p.Lower + p.Number + p.Symbol + p.Upper) == 0 {
		return errors.New("At least one chracter class must be required in the Rules. Lower, Number, Symbol, and Upper were all zero (0)")
	}

	if (p.Symbol > 0) && (p.ValidSymbols != nil) && (len(p.ValidSymbols) == 0) {
		return errors.New("Special symbols are required but none were provided. Set ValidSymbols to nil to use default Symbols. Is ValidSymbols provided, len must be greater or equal to one (1)")
	}
	return nil

}

func (p *Password) generate(strong bool) (password string, err error) {

	err = p.validateArgs()
	if err != nil {
		return "", err
	}

	// build our rune slice of default characters
	chars := []rune{}

	// will hold our password
	pwd := []rune{}

	// holds random characters to be appended to the password
	var randChars []rune

	var priorLen int

	// add min # of upper case characters
	if p.Upper > 0 {
		priorLen = len(chars)
		chars = append(chars, []rune(UpperCaseLetters)...)
		// log.Println(string(chars[priorLen : priorLen+26]))
		randChars = getChars(p.Upper, chars[priorLen:priorLen+26], strong)
		pwd = append(pwd, randChars...)
	}

	// add min # of lower case characters
	if p.Lower > 0 {
		priorLen = len(chars)
		chars = append(chars, []rune(LowerCaseLetters)...)
		// log.Println(string(chars[priorLen : priorLen+26]))
		randChars = getChars(p.Lower, chars[priorLen:priorLen+26], strong)
		pwd = append(pwd, randChars...)
	}

	// add min # of numbers
	if p.Number > 0 {
		priorLen = len(chars)
		chars = append(chars, []rune(Numbers)...)
		randChars = getChars(p.Number, chars[priorLen:priorLen+10], strong)
		// log.Println(string(chars[priorLen : priorLen+10]))
		pwd = append(pwd, randChars...)
	}

	// add min # of special characters
	if p.Symbol > 0 {
		priorLen := len(chars)
		// append default special chars unless user identified some
		if len(p.ValidSymbols) == 0 {
			chars = append(chars, []rune(Symbols)...)
		} else {
			chars = append(chars, p.ValidSymbols...)
		}
		randChars = getChars(p.Symbol, chars[priorLen:], strong)
		// log.Println(string(chars[priorLen:]))
		pwd = append(pwd, randChars...)
	}

	// check password length. if still too short, append
	// remaining random chars from full set to meet min length.
	if len(pwd) < p.MinLength {
		remain := p.MinLength - len(pwd)
		randChars = getChars(remain, chars[:], strong)
		// log.Println(string(chars[:]))
		pwd = append(pwd, randChars...)
	}

	// randomize our password
	shuffle(pwd)

	return string(pwd), nil

}

// Generate returns a password using the passed rules and
// and uses the pseudo-random number generator in the
// math/rand library. It is not cryptographically secure!
func (p *Password) Generate() (password string, err error) {

	return p.generate(false)

}

// GenerateStrong returns a password using the passed rules
// and uses the cryptographically secure pseudorandom number
// generator in the crypto/rand library
func (p *Password) GenerateStrong() (password string, err error) {

	return p.generate(true)

}

func getChars(count int, runes []rune, strong bool) []rune {

	numRunes := len(runes)
	numRunesBig := big.NewInt(int64(numRunes))
	selRunes := []rune{}
	var idx int
	var bidx *big.Int
	var err error

	for i := 0; i < count; i++ {
		if numRunes == 1 {
			idx = 0
		} else {
			if strong {
				bidx, err = crytporand.Int(crytporand.Reader, numRunesBig)
				if err != nil {
					panic(err)
				}
				idx = int(bidx.Int64())
			} else {
				idx = rand.Intn(numRunes)
			}
			selRunes = append(selRunes, runes[idx])

		}

	}

	return selRunes

}

// Uses rand.Shuffle introduced in Go 1.10. If running earlier
// version, use the version below and comment this one out.
func shuffle(slice interface{}) {
	rv := reflect.ValueOf(slice)
	swap := reflect.Swapper(slice)
	length := rv.Len()
	rand.Shuffle(length, swap)
}

// func shuffleRune(slice []rune) {
// 	length := len(slice)
// 	for i := length - 1; i > 0; i-- {
// 		j := rand.Intn(i + 1)
// 		slice[i], slice[j] = slice[j], slice[i]
// 	}
// }
