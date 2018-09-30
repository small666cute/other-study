package test;

import org.owasp.validator.html.AntiSamy;
import org.owasp.validator.html.CleanResults;
import org.owasp.validator.html.Policy;

public class AntiSamyApplication {
    public static void main(String[] args)
    {
        AntiSamy as = new AntiSamy();
        String taintedHtml="&#x3c;&#x69;&#x6d;&#x67;&#x20;&#x73;&#x72;&#x63;&#x3d;&#x78;&#x20;&#x6f;&#x6e;&#x65;&#x72;&#x72;&#x6f;&#x72;&#x3d;&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;&#x3e;";
        //taintedHtml="<a href=\"data:text/html;base64, PGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KDEpPg==\">test</a>";
        //taintedHtml="\\74\\151\\155\\147\\40\\163\\162\\143\\75\\170\\40\\157\\156\\145\\162\\162\\157\\162\\75\\141\\154\\145\\162\\164\\50\\61\\51\\76";
        //taintedHtml="\\u003c\\u0069\\u006d\\u0067\\u0020\\u0073\\u0072\\u0063\\u003d\\u0078\\u0020\\u006f\\u006e\\u0065\\u0072\\u0072\\u006f\\u0072\\u003d\\u0061\\u006c\\u0065\\u0072\\u0074\\u0028\\u0031\\u0029\\u003e";
        taintedHtml="eval(\"\\x61\\x6c\\x65\\x72\\x74\\x28\\x27\\x58\\x53\\x53\\x27\\x29\");";
        //taintedHtml="<div style=\"xss:&#101;&#120;&#112;&#114;&#101;&#115;&#115;&#105;&#111;&#110;(alert(1));\"></div>";
        //taintedHtml="<img src=\"javascript：eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))\">";
        //taintedHtml="<style>\n" +"BODY { background: url(http://127.0.0.1/xss.gif) }\n" +"</style>";
        taintedHtml="'%22%3E%3Cimg+src%3Dx+onerror%3Dalert(document.cookie)%3E";
        taintedHtml="<a href=\"&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#37;&#53;&#99;&#37;&#55;&#53;&#37;&#51;&#48;&#37;&#51;&#48;&#37;&#51;&#54;&#37;&#51;&#49;&#37;&#53;&#99;&#37;&#55;&#53;&#37;&#51;&#48;&#37;&#51;&#48;&#37;&#51;&#54;&#37;&#54;&#51;&#37;&#53;&#99;&#37;&#55;&#53;&#37;&#51;&#48;&#37;&#51;&#48;&#37;&#51;&#54;&#37;&#51;&#53;&#37;&#53;&#99;&#37;&#55;&#53;&#37;&#51;&#48;&#37;&#51;&#48;&#37;&#51;&#55;&#37;&#51;&#50;&#37;&#53;&#99;&#37;&#55;&#53;&#37;&#51;&#48;&#37;&#51;&#48;&#37;&#51;&#55;&#37;&#51;&#52;&#40;&#51;&#41;\">test3</a>";
        taintedHtml="</textarea>";
        taintedHtml="/* */";
        taintedHtml="<video src=x onerror=prompt(1);>";
        try{
            Policy policy = Policy.getInstance("\\antisamy\\antisamy-tinymce.xml");
            CleanResults cr = as.scan(taintedHtml, policy);
            System.out.print(cr.getCleanHTML());
        }
        catch(Exception ex) {
            ex.printStackTrace();
        }
    }
}