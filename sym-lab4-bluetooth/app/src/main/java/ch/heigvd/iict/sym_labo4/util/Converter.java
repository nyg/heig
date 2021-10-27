package ch.heigvd.iict.sym_labo4.util;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Calendar;
import java.util.TimeZone;

import no.nordicsemi.android.ble.data.Data;

/**
 * PROJECT     : LABORATOIRE 4
 * AUTHORS     : Mickael Bonjour, Nikolaos Garanis, Samuel Mettler
 * DATE        : 08/01/2020
 * VERSION     : 1
 * DESCRIPTION : A util class for methods to convert data from and to the Data
 *               class.
 */
public final class Converter {

    /**
     * Converts the Data instance to a 32-bit integer.
     *
     * @return the 32-bit integer or null if data is empty or has not enough data
     */
    public static Integer toInteger(Data data) {
        return data.getIntValue(Data.FORMAT_UINT32, 0);
    }

    /**
     * Converts the Data instance to a 16-bit integer.
     *
     * @return the 16-bit integer (returned in an Integer instance) or null if
     * data is empty or has not enough data
     */
    public static Integer toShort(Data data) {
        return data.getIntValue(Data.FORMAT_UINT16, 0);
    }

    /**
     * Converts the Data instance to a 8-bit integer.
     *
     * @return the 8-bit integer (returned in an Integer instance) or null if
     * data is empty or has not enough data
     */
    public static Integer toByte(Data data) {
        return data.getIntValue(Data.FORMAT_UINT8, 0);
    }

    /**
     * Converts the Data instance to a Calendar instance.
     *
     * @return the Calendar instance or null if data is empty or has not enough
     * data
     */
    public static Calendar toCalendar(Data data) {

        if (data.size() != 10) {
            return null;
        }

        Integer year = toShort(data);
        byte[] bytes = data.getValue();

        Calendar calendar = Calendar.getInstance(TimeZone.getDefault());
        calendar.set(year, bytes[2] - 1, bytes[3], bytes[4], bytes[5], bytes[6]);
        // No need to read bytes[7] (day of week), Calendar will automatically calculate it.
        return calendar;
    }

    /**
     * Converts an integer to a Data instance.
     */
    public static Data toData(int value) {
        return new Data(toBytes(value));
    }

    /**
     * Converts a Calendar instance to a Data instance.
     */
    public static Data toData(Calendar calendar) {

        byte[] year = toBytes(calendar.get(Calendar.YEAR));

        return new Data(new byte[] {
                year[0], year[1],                           // year
                (byte) (calendar.get(Calendar.MONTH) + 1),  // month, 1-12
                (byte) calendar.get(Calendar.DAY_OF_MONTH), // day of month, 1-31
                (byte) calendar.get(Calendar.HOUR_OF_DAY),  // hour, 0-23
                (byte) calendar.get(Calendar.MINUTE),       // minutes, 0-59
                (byte) calendar.get(Calendar.SECOND),       // seconds, 0-59
                (byte) calendar.get(Calendar.DAY_OF_WEEK),  // day of week, 1-7
                0,                                          // fraction 256
                0                                           // adjust reason
        });
    }

    /**
     * Converts an integer to a byte array (little-endian).
     */
    private static byte[] toBytes(int value) {
        return ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array();
    }

    private Converter() {
        throw new IllegalStateException("Class cannot be instanciated.");
    }
}
