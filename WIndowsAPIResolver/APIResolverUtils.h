#pragma once

template <typename T>
size_t stringLen(T* const string) {
	size_t len = 0;
	while (string[len] != '\0')
		++len;

	return len;
}

template <typename T>
size_t stringSize(const T* const string) {
	return stringLen(string) * sizeof(T);
}

template <typename T>
bool compareString(T* str1, T* str2) {
	const size_t sizeFirst = stringLen(str1);
	const size_t sizeSecond = stringLen(str2);

	if (sizeFirst != sizeSecond)
		return false;
	
	for (size_t i = 0; i < sizeFirst; ++i) {
		if (str1[i] != str2[i])
			return false;
	}
	return true;

}