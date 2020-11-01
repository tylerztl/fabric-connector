package config

var isGM bool = false

func InitAlgorithm(algo string)  error{
	if algo == "SM2"{
		isGM = true
	}else {
		isGM = false
	}
	return nil
}

func IsGM() bool{
	return isGM
}