document.addEventListener('DOMContentLoaded', () => {
	// --- Выбор элементов DOM ---
	const cipherTypeSelect = document.getElementById('cipher-type')
	const paramsContainer = document.getElementById('params-container')
	const allParams = document.querySelectorAll('.param')

	const inputText = document.getElementById('input-text')
	const outputText = document.getElementById('output-text')

	const base64AlphabetInput = document.getElementById('base64-alphabet')
	const caesarShiftInput = document.getElementById('caesar-shift')
	const xorKeyInput = document.getElementById('xor-key')
	const xorKeyTypeSelect = document.getElementById('xor-key-type') // Новый элемент

	const encodeBtn = document.getElementById('encode-btn')
	const decodeBtn = document.getElementById('decode-btn')
	const themeSwitcher = document.getElementById('theme-switcher')

	// --- Константы ---
	const DEFAULT_BASE64_ALPHABET =
		'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

	// --- ЛОГИКА ШИФРОВАНИЯ ---

	// 1. Base64 (с улучшенной обработкой ошибок)
	const base64 = {
		encode: (str, alphabet = DEFAULT_BASE64_ALPHABET) => {
			try {
				if (alphabet.length !== 64 || new Set(alphabet.split('')).size !== 64) {
					throw new Error(
						`Алфавит Base64 должен содержать 64 уникальных символа. Вы ввели: ${alphabet.length}.`
					)
				}
				const utf8Str = unescape(encodeURIComponent(str))
				let binary = ''
				for (let i = 0; i < utf8Str.length; i++) {
					binary += utf8Str[i].charCodeAt(0).toString(2).padStart(8, '0')
				}

				let encoded = ''
				for (let i = 0; i < binary.length; i += 6) {
					let chunk = binary.slice(i, i + 6).padEnd(6, '0')
					encoded += alphabet[parseInt(chunk, 2)]
				}

				const padding = (3 - (utf8Str.length % 3)) % 3
				return encoded.slice(0, encoded.length - padding) + '='.repeat(padding)
			} catch (e) {
				return `Ошибка кодирования: ${e.message}`
			}
		},
		decode: (str, alphabet = DEFAULT_BASE64_ALPHABET) => {
			try {
				if (alphabet.length !== 64 || new Set(alphabet.split('')).size !== 64) {
					throw new Error(
						`Алфавит Base64 должен содержать 64 уникальных символа. Вы ввели: ${alphabet.length}.`
					)
				}
				const alphabetMap = {}
				for (let i = 0; i < alphabet.length; i++) alphabetMap[alphabet[i]] = i

				const strWithoutPadding = str.replace(/=+$/, '')
				let binary = ''
				for (let i = 0; i < strWithoutPadding.length; i++) {
					const char = strWithoutPadding[i]
					if (alphabetMap[char] === undefined)
						throw new Error(`Символ "${char}" не найден в алфавите.`)
					binary += alphabetMap[char].toString(2).padStart(6, '0')
				}

				let decodedBytes = []
				for (let i = 0; i < binary.length; i += 8) {
					if (i + 8 <= binary.length) {
						decodedBytes.push(parseInt(binary.slice(i, i + 8), 2))
					}
				}

				const uint8Array = new Uint8Array(decodedBytes)
				// TextDecoder правильно обрабатывает многобайтовые UTF-8 символы
				const decoder = new TextDecoder('utf-8')
				return decoder.decode(uint8Array)
			} catch (e) {
				return `Ошибка декодирования: ${e.message}`
			}
		},
	}

	// 2. Шифр Цезаря (без изменений)
	const caesarCipher = (str, shift, decode = false) => {
		// ... (код остался прежним)
		const s = decode ? -shift : shift
		const alphabetRU = 'абвгдеёжзийклмнопрстуфхцчшщъыьэюя'
		const alphabetEN = 'abcdefghijklmnopqrstuvwxyz'

		return str
			.split('')
			.map(char => {
				const lowerChar = char.toLowerCase()
				if (alphabetRU.includes(lowerChar)) {
					const isUpper = char !== lowerChar
					const index = alphabetRU.indexOf(lowerChar)
					const newIndex = (index + (s % 33) + 33) % 33
					const newChar = alphabetRU[newIndex]
					return isUpper ? newChar.toUpperCase() : newChar
				} else if (alphabetEN.includes(lowerChar)) {
					const isUpper = char !== lowerChar
					const index = alphabetEN.indexOf(lowerChar)
					const newIndex = (index + (s % 26) + 26) % 26
					const newChar = alphabetEN[newIndex]
					return isUpper ? newChar.toUpperCase() : newChar
				}
				return char
			})
			.join('')
	}

	// 3. XOR шифрование (полностью переработано)
	const parseKeyToBytes = (keyStr, type) => {
		if (!keyStr) throw new Error('Ключ не может быть пустым.')

		switch (type) {
			case 'text':
				return keyStr.split('').map(c => c.charCodeAt(0))
			case 'hex':
				const cleanHex = keyStr.replace(/0x|[\s,]/g, '')
				if (/[^0-9a-fA-F]/.test(cleanHex) || cleanHex.length % 2 !== 0) {
					throw new Error(
						'Неверный формат Hex ключа. Используйте символы 0-9, A-F и парное их количество.'
					)
				}
				const hexBytes = []
				for (let i = 0; i < cleanHex.length; i += 2) {
					hexBytes.push(parseInt(cleanHex.substr(i, 2), 16))
				}
				return hexBytes
			case 'dec':
				const decParts = keyStr.trim().split(/[\s,]+/)
				const decBytes = decParts.map(p => parseInt(p, 10))
				if (decBytes.some(b => isNaN(b) || b < 0 || b > 255)) {
					throw new Error(
						'Неверный формат Dec ключа. Используйте числа от 0 до 255, разделенные пробелом или запятой.'
					)
				}
				return decBytes
			default:
				throw new Error('Неизвестный тип ключа.')
		}
	}

	const xorCipher = (str, keyBytes) => {
		// TextEncoder преобразует строку в массив байтов UTF-8, что корректно работает с любыми символами
		const textBytes = new TextEncoder().encode(str)
		const resultBytes = new Uint8Array(textBytes.length)

		for (let i = 0; i < textBytes.length; i++) {
			resultBytes[i] = textBytes[i] ^ keyBytes[i % keyBytes.length]
		}

		// TextDecoder пытается расшифровать байты как UTF-8.
		// Если результат не является валидной UTF-8 последовательностью, могут быть проблемы.
		// Для бинарных данных лучше выводить в Hex, но для текста это основной способ.
		try {
			return new TextDecoder('utf-8', { fatal: true }).decode(resultBytes)
		} catch (e) {
			// Если результат не является валидным текстом, вернем его в виде Hex-строки
			return Array.from(resultBytes)
				.map(b => b.toString(16).padStart(2, '0'))
				.join(' ')
		}
	}

	// --- УПРАВЛЕНИЕ ИНТЕРФЕЙСОМ ---

	const updateVisibleParams = () => {
		const selectedCipher = cipherTypeSelect.value
		allParams.forEach(param => {
			if (param.dataset.param === selectedCipher) {
				param.classList.remove('hidden')
			} else {
				param.classList.add('hidden')
			}
		})
	}

	// --- ОБРАБОТЧИКИ ДЕЙСТВИЙ ---

	const processCipher = isDecoding => {
		const text = inputText.value
		const cipher = cipherTypeSelect.value
		let result = ''

		try {
			switch (cipher) {
				case 'base64':
					const alphabet =
						base64AlphabetInput.value.trim() || DEFAULT_BASE64_ALPHABET
					result = isDecoding
						? base64.decode(text, alphabet)
						: base64.encode(text, alphabet)
					break
				case 'caesar':
					const shift = parseInt(caesarShiftInput.value, 10)
					result = caesarCipher(text, shift, isDecoding)
					break
				case 'xor':
					// XOR симметричен, поэтому isDecoding не используется
					const keyBytes = parseKeyToBytes(
						xorKeyInput.value,
						xorKeyTypeSelect.value
					)
					result = xorCipher(text, keyBytes)
					break
			}
		} catch (e) {
			result = `Ошибка: ${e.message}`
		}

		outputText.value = result
		saveState()
	}

	// --- УМНЫЙ UI ДЛЯ XOR КЛЮЧА ---
	const handleXorKeyInput = () => {
		const key = xorKeyInput.value.trim().toLowerCase()
		if (key.startsWith('0x')) {
			xorKeyTypeSelect.value = 'hex'
			xorKeyTypeSelect.disabled = true
		} else {
			xorKeyTypeSelect.disabled = false
		}
		saveState()
	}

	// --- УПРАВЛЕНИЕ ТЕМОЙ ---

	const switchTheme = theme => {
		document.documentElement.setAttribute('data-theme', theme)
		localStorage.setItem('reversify-theme', theme)
		themeSwitcher.textContent = theme === 'dark' ? '☀️' : '🌙'
	}

	// --- СОХРАНЕНИЕ И ЗАГРУЗКА СОСТОЯНИЯ (localStorage) ---

	const saveState = () => {
		const state = {
			cipher: cipherTypeSelect.value,
			inputText: inputText.value,
			base64Alphabet: base64AlphabetInput.value,
			caesarShift: caesarShiftInput.value,
			xorKey: xorKeyInput.value,
			xorKeyType: xorKeyTypeSelect.value,
		}
		localStorage.setItem('reversify-state', JSON.stringify(state))
	}

	const loadState = () => {
		const savedTheme =
			localStorage.getItem('reversify-theme') ||
			(window.matchMedia('(prefers-color-scheme: dark)').matches
				? 'dark'
				: 'light')
		switchTheme(savedTheme)

		const savedState = localStorage.getItem('reversify-state')
		if (savedState) {
			const state = JSON.parse(savedState)
			cipherTypeSelect.value = state.cipher || 'base64'
			inputText.value = state.inputText || ''
			base64AlphabetInput.value = state.base64Alphabet || ''
			caesarShiftInput.value = state.caesarShift || '3'
			xorKeyInput.value = state.xorKey || ''
			xorKeyTypeSelect.value = state.xorKeyType || 'text'
		}

		updateVisibleParams()
		handleXorKeyInput() // Проверяем ключ XOR при загрузке
	}

	// --- НАЗНАЧЕНИЕ ОБРАБОТЧИКОВ СОБЫТИЙ ---

	// --- НАЗНАЧЕНИЕ ОБРАБОТЧИКОВ СОБЫТИЙ ---
	cipherTypeSelect.addEventListener('change', () => {
		updateVisibleParams()
		saveState()
	})

	encodeBtn.addEventListener('click', () => processCipher(false))
	decodeBtn.addEventListener('click', () => processCipher(true))

	themeSwitcher.addEventListener('click', () => {
		const currentTheme = document.documentElement.getAttribute('data-theme')
		switchTheme(currentTheme === 'dark' ? 'light' : 'dark')
	})

	// Сохранение при вводе
	xorKeyInput.addEventListener('input', handleXorKeyInput)
	;[inputText, base64AlphabetInput, caesarShiftInput, xorKeyTypeSelect].forEach(
		input => {
			input.addEventListener('input', saveState)
		}
	)

	// --- ИНИЦИАЛИЗАЦИЯ ---
	loadState()
})
