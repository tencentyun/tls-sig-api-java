## 使用构建工具集成

### maven
```xml
<dependencies>
    <dependency>
        <groupId>com.github.tencentyun</groupId>
        <artifactId>tls-sig-api</artifactId>
        <version>1.2</version>
    </dependency>
</dependencies>
```

### gradle
```java
dependencies {
    compile 'com.github.tencentyun:tls-sig-api:1.2'
}
```

## 生成 sig

### 默认有效期接口
```java
import com.tls.tls_sigature.*;

GenTLSSignatureResult result = tls_sigature.genSig(140000000, "xiaojun", priKeyContent);
System.out.println(result.urlSig);
```

### 指定有效期接口
```java
import com.tls.tls_sigature.*;

GenTLSSignatureResult result = tls_sigature.GenTLSSignatureEx(140000000, "xiaojun", priKeyContent, 24*3600*180);
System.out.println(result.urlSig);
```
