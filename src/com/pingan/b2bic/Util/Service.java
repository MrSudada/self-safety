package com.pingan.b2bic.Util;

import static com.pingan.b2bic.Util.YQUtil.fill;

public class Service {

    private static Service service;

    private static Object plock = new Object();

    private Object plockSN = new Object();

    private int g_sn;

    public static Service getInstance() {
        if (service == null) {
            synchronized (plock) {
                service = new Service();
            }
        }
        return service;
    }

    /**
     * 取下一个流水号
     *
     * @return
     */
    public String nextSn() {
        int sn;
        synchronized (plockSN) {
            g_sn++;
            if (g_sn > 99999999) {
                g_sn = 1;
            }
            sn = g_sn;
        }
        return fill(("" + sn), '0', 8, true);
    }
}
