import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

public class SimpleCrypto {
    //Лень было каждый раз писать пути в консоль,потому задал их через статические переменные.
    //Путь исходного файла
    private static final Path plainTextFilePath = Path.of("test/pFile.txt");
    //Путь зашифрованного файла
    private static final Path encryptedTextFilePath = Path.of("test/encFile.txt");
    //Путь расшифрованного файла
    private static final Path decryptedTextFilePath = Path.of("test/decFile.txt");
    //Путь файла, полученного методом брутфорса
    private static final Path bruteforceTextFilePath = Path.of("test/bfFile.txt");
    //Русский алфавит с небольшим набором основных знаков препинания.
    public static final String alphabet = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдеёжзийклмнопрстуфхцчшщъыьэюя.,\":-!? ";
    public static void main(String[] args) throws IOException {
        encryptText(plainTextFilePath, encryptedTextFilePath, 1);
        decryptText(encryptedTextFilePath, decryptedTextFilePath, 1);
        bruteforce(encryptedTextFilePath, bruteforceTextFilePath);
        //getStats(firstVolTextFilePath);
    }

    /*  Функция кодирования шифром Цезаря.
        Входные парметры:
                            - путь исходного файла;
                            - путь зашифрованного файла;
                            - ключ (сдвиг при кодировании).
        Примечание: Символы новой строки и возвращение коретки не затрагивается шифрованием, как символы не в ходящие в заданный алфавит.
    */
    public static void encryptText(Path plainTextFilePath, Path encryptedTextFilePath, int key) throws IOException {
        /*  Проверка на наличие зашифрованного файла, если есть старый с таким же названием, удаляем и создаём новый.
            При отсутсвии исходного файла выскочит соответствующее исключение. */
        if(Files.exists(encryptedTextFilePath)) {
            Files.delete(encryptedTextFilePath);
        }
        Files.createFile(encryptedTextFilePath);
        try(FileChannel inputStream = FileChannel.open(plainTextFilePath); FileChannel outputStream = FileChannel.open(encryptedTextFilePath, StandardOpenOption.WRITE)){
            ByteBuffer inputBuffer = ByteBuffer.allocate(65536);
            while(inputStream.read(inputBuffer) > 0) {
                inputBuffer.flip();
                //Преоброзование байтов в символы.
                CharBuffer charBuffer = StandardCharsets.UTF_8.decode(inputBuffer);
                //Сдвиг с заданным ключём
                for (int i = 0; i < charBuffer.length(); i++) {
                    //Проверка на принадлежность символов заданному алфавиту
                    if(alphabet.indexOf(charBuffer.charAt(i)) >= 0) {
                        charBuffer.put(i, alphabet.charAt((alphabet.indexOf(charBuffer.charAt(i)) + key) % alphabet.length()));
                    }
                }
                inputBuffer.flip();
                inputBuffer.clear();
                ByteBuffer outputBuffer = ByteBuffer.allocate(charBuffer.length() * 20);
                outputBuffer.put(StandardCharsets.UTF_8.encode(charBuffer));
                outputBuffer.flip();
                outputStream.write(outputBuffer);
                outputBuffer.flip();
                outputBuffer.clear();
            }
            System.out.println("Шифорование завершено!");
        }
    }

    /*  Функция декодирования  шифром Цезаря.
        Входные парметры:
                            - путь зашифрованного файла;
                            - путь расшифрованного файла;
                            - ключ (сдвиг при кодировании).
    */
    public static void decryptText(Path encryptedTextFilePath, Path decryptedTextFilePath, int key) throws IOException {
        if(Files.exists(decryptedTextFilePath)) {
            Files.delete(decryptedTextFilePath);
        }
        Files.createFile(decryptedTextFilePath);
        try(FileChannel inputStream = FileChannel.open(encryptedTextFilePath); FileChannel outputStream = FileChannel.open(decryptedTextFilePath, StandardOpenOption.WRITE)){
            ByteBuffer inputBuffer = ByteBuffer.allocate(65536);
            while(inputStream.read(inputBuffer) > 0) {
                inputBuffer.flip();
                CharBuffer charBuffer = StandardCharsets.UTF_8.decode(inputBuffer);
                for (int i = 0; i < charBuffer.length(); i++) {
                    if (alphabet.indexOf(charBuffer.charAt(i)) >= 0) {
                        charBuffer.put(i, alphabet.charAt((alphabet.indexOf(charBuffer.charAt(i)) + alphabet.length() - (key) % alphabet.length()) % alphabet.length()));
                    }
                }
                inputBuffer.flip();
                inputBuffer.clear();
                ByteBuffer outputBuffer = ByteBuffer.allocate(charBuffer.length() * 2);
                outputBuffer.put(StandardCharsets.UTF_8.encode(charBuffer));
                outputBuffer.flip();
                outputStream.write(outputBuffer);
                outputBuffer.flip();
                outputBuffer.clear();
            }
            System.out.println("Расшифровали!");
        }
    }

    /*  Функция расшифрования перебора ключей (brute force).
        Принимает на вход путь к исходному файлу, путь куда записать файл.
        Входные парметры:
                            - путь к  файлу, для расшифрования;
                            - путь для расшифрованнного файла.
    */
    public static void bruteforce(Path encryptedTextFilePath, Path bruteforceTextFilePath) throws IOException{
        if(Files.exists(bruteforceTextFilePath)) {
            Files.delete(bruteforceTextFilePath);
        }
        Files.createFile(bruteforceTextFilePath);
        try(FileChannel inputStream = FileChannel.open(encryptedTextFilePath); FileChannel outputStream = FileChannel.open(bruteforceTextFilePath, StandardOpenOption.WRITE)){
            ByteBuffer inputBuffer = ByteBuffer.allocate(65536);
            int key = 0;
            while(inputStream.read(inputBuffer) > 0) {
                inputBuffer.flip();
                //Преоброзование байтов в символы.
                CharBuffer charBuffer = StandardCharsets.UTF_8.decode(inputBuffer);
                inputBuffer.flip();
                inputBuffer.clear();
                //Сдвиг с заданным ключём
                boolean isViable = false;
                while (!isViable) {
                    for (int i = 0; i < charBuffer.length(); i++) {
                        //Проверка на принадлежность символов алфавиту, в том числе символы начала новой строки и возврата в начало строки
                        if (alphabet.indexOf(charBuffer.charAt(i)) >= 0) {
                            charBuffer.put(i, alphabet.charAt((alphabet.indexOf(charBuffer.charAt(i)) + alphabet.length() - 1) % alphabet.length()));
                        }
                    }
                    isViable = validateBruteforce(charBuffer);
                    key++;
                    //Если мы пербрали все возможные варианты: количество перепробованных вариантов вышло за размер алфавита
                    if(key > alphabet.length()) {
                        System.out.println("Брутфорс провалился!");
                        break;
                    }
                }
                System.out.println("Ключ по модулю " + alphabet.length() + " равен: " + (key % alphabet.length()));
                ByteBuffer outputBuffer = ByteBuffer.allocate(charBuffer.length() * 2);
                outputBuffer.put(StandardCharsets.UTF_8.encode(charBuffer));
                outputBuffer.flip();
                outputStream.write(outputBuffer);
                outputBuffer.flip();
                outputBuffer.clear();
            }
            System.out.println("Успех!");
        }
    }

    //Функция проверки получившегося при декодировании текста на правильность знаков пунктуации. На вход принимает проверяемое слово.
    private static boolean validatePunctuationMarks(String word) {
        //Проверка на кавычки: они либо в конце слова либо в начале (пример: прямая речь из нескольких слов), либо в начале и конце (пример: название из одного слова)
        int indexOfLastCharWithoutQuotes = word.length() - 1;
        if(word.contains("\"") && !(word.indexOf("\"") == indexOfLastCharWithoutQuotes || word.indexOf("\"") == 0)) {
            return false;
        }
        //Если будут кавычки в конце слова, то точки могут быть внутри кавычек. Но, если вариант когда прямая речь "П", - а. и вариант ковыче в конце предложения с точкой "П".
        //то условие не выполнится и проверка на точку и запятую в конце слова сработает верно.
        if(word.contains("\"") && word.charAt(indexOfLastCharWithoutQuotes) == '\"') {
            indexOfLastCharWithoutQuotes = word.length() - 2;
        }
        //Доп суловие для закрывающих кавычек, для проверки рассказа Чехова "Бабы"
        if(word.contains("»") && word.charAt(indexOfLastCharWithoutQuotes) == '»') {
            indexOfLastCharWithoutQuotes = word.length() - 2;
        }
        //Проверка на двоеточие
        if(word.contains(":") && word.indexOf(":") != indexOfLastCharWithoutQuotes) {
            return false;
        }
        if(word.contains(",") && word.indexOf(",") != indexOfLastCharWithoutQuotes) {
            return false;
        }
        //проврка для точки с учетом случаев ".", "?..", "!..", "...". Кстати, у троеточия тоже есть отдельный сиивол.
        if(word.contains(".") && word.charAt(indexOfLastCharWithoutQuotes) != '.' && word.indexOf(".") < (indexOfLastCharWithoutQuotes - 2)) {
            return false;
        }
        if(word.contains("!") && (word.indexOf("!") != (indexOfLastCharWithoutQuotes - 2) && word.indexOf("!") != indexOfLastCharWithoutQuotes)) {
            return false;
        }
        //проврка для знака вопроса с учетом случаев "?..", "?!", "?".
        if(word.contains("?") && word.indexOf("?") < (indexOfLastCharWithoutQuotes - 2) ) {
            return false;
        }
        if (word.contains("-")) {
            if (word.length() == 2) {
                return false;
            } else if (word.length() > 2) {
                return word.indexOf("-") > 0 && word.indexOf("-") < indexOfLastCharWithoutQuotes;
            }
        }
        return true;
    }

    //Функция проверки получившегося при декодировании текста на правильность заглавных букв. На вход принимает проверяемое слово
    private static boolean validateCapitalLetters(String word) {
        char[] tempChar = word.toCharArray();
        int start = 1;
        if(tempChar[0] == '\"' || tempChar[0] == '”' || tempChar[0] == '«') {
            start = 2;
        }
        for (int i = start; i < tempChar.length; i++) {
            if(Character.isUpperCase(tempChar[i])) {
                return false;
            }
        }
        return true;
    }

    //Функция, которая проверяет успешно ли взломан закодированный файл
    private static boolean validateBruteforce(CharBuffer charBuffer) {
        String[] words = charBuffer.toString().split("\r\n| ");
        for (String word : words) {
            if(word.equals("")) {
                continue;
            }
            if (!validatePunctuationMarks(word) || !validateCapitalLetters(word)) {
                return false;
            }
        }
        return true;
    }
}