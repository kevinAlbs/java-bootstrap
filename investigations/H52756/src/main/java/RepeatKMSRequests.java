import com.mongodb.ClientEncryptionSettings;
import com.mongodb.ConnectionString;
import com.mongodb.MongoClientSettings;
import com.mongodb.MongoNamespace;
import com.mongodb.client.MongoClients;
import com.mongodb.client.model.vault.DataKeyOptions;
import com.mongodb.client.model.vault.EncryptOptions;
import com.mongodb.client.vault.ClientEncryptions;
import org.bson.BsonBinary;
import org.bson.BsonDocument;
import org.bson.BsonString;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Map;

public class RepeatKMSRequests {

    static final ConnectionString CONNECTION_STRING = new ConnectionString("mongodb://localhost:27017");
    static final MongoNamespace VAULT_NAMESPACE = new MongoNamespace("csfle", "vault");
    static final String ENCRYPTION_ALGORITHM = "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic";
    protected static final Map<String, Map<String, Object>> KMS_PROVIDERS = Map.of("aws",
            Map.of("accessKeyId", getRequiredEnv("AWS_ACCESS_KEY_ID"),
                    "secretAccessKey", getRequiredEnv("AWS_SECRET_ACCESS_KEY")));
    static final String DATABASE = "test";
    static final String COLLECTION = "coll";

    private static String getRequiredEnv (String name) {
        String value = System.getenv(name);
        if (null == value) {
            throw new RuntimeException("Error: required environment variable not set: " + name);
        }
        return value;
    }

    public static void main(String[] args) throws IOException {
        var ceSettings = ClientEncryptionSettings.builder()
                .keyVaultMongoClientSettings(MongoClientSettings.builder()
                        .applyConnectionString(CONNECTION_STRING)
                        .build())
                .keyVaultNamespace(VAULT_NAMESPACE.getFullName()).kmsProviders(KMS_PROVIDERS).build();

        // Drop prior data.
        try (var client = MongoClients.create(MongoClientSettings.builder()
                .applyConnectionString(CONNECTION_STRING)
                .build())) {
            client.getDatabase(VAULT_NAMESPACE.getDatabaseName()).getCollection(VAULT_NAMESPACE.getCollectionName()).drop();
            var collection = client.getDatabase(DATABASE).getCollection(COLLECTION);
            collection.drop();
        }

        // Create a DEK.
        BsonBinary dataKey;
        try (var encryptor = ClientEncryptions.create(ceSettings)) {
            var dko = new DataKeyOptions();
            dko.masterKey(new BsonDocument().append("key", new BsonString(getRequiredEnv("AWS_KEY_ID"))).append("region", new BsonString("us-east-1")));
            dataKey = encryptor.createDataKey("aws", dko);
        }

        // Repeatedly use the DEK. This is expected to result in one KMS request per iteration.
        var startTimeNs = System.nanoTime();
        var totalRequests = 1000;
        var iterTimesSec = new ArrayList<Double>();
        System.out.printf("Sending %d requests ... begin\n", totalRequests);
        for (var i = 0; i < totalRequests; i++) {
            var iterStartTimeNs = System.nanoTime();

            // Use a new ClientEncryption on each iteration. The new ClientEncryption does not have a cached DEK and will send a new KMS request.
            try (var encryptor = ClientEncryptions.create(ceSettings)) {
                encryptor.encrypt(new BsonString("foo"),
                        new EncryptOptions(ENCRYPTION_ALGORITHM).keyId(dataKey));
            }

            var iterEndTimeNs = System.nanoTime();
            iterTimesSec.add((iterEndTimeNs - iterStartTimeNs) / 1_000_000_000.0);

            if (i % (totalRequests / 10) == 0) {
                // Print dot to show progress.
                System.out.print(".");
                System.out.flush();
            }
        }
        System.out.println();
        System.out.printf("Sending %d requests ... end\n", totalRequests);

        // Print statistics.
        var endTimeNs = System.nanoTime();
        var durationSec = (endTimeNs - startTimeNs) / 1_000_000_000.0;
        var requestsPerSecond = totalRequests / durationSec;
        var maxRequestTimeSec = Collections.max(iterTimesSec);
        Collections.sort(iterTimesSec);
        var medianRequestTimeSec = iterTimesSec.get(iterTimesSec.size() / 2);

        System.out.printf("Total requests run    : %d\n",totalRequests);
        System.out.printf("Duration              : %.2fs\n",durationSec);
        System.out.printf("Avg requests/sec      : %.2f\n", requestsPerSecond);
        System.out.printf("Max request time      : %.2fs\n", maxRequestTimeSec);
        System.out.printf("Median request time   : %.2fs\n", medianRequestTimeSec);

        // Print a simple histogram of 10 buckets.
        System.out.println("Histogram");
        var nBuckets = 10;
        var rangeSec = Collections.max(iterTimesSec) / nBuckets;
        var buckets = new int[nBuckets];
        for (var iterTimeSec : iterTimesSec) {
            var bucketIdx = (int) (iterTimeSec / rangeSec);
            if (bucketIdx == nBuckets) {
                // Include maximum time in the last bucket.
                bucketIdx = bucketIdx - 1;
            }
            buckets[bucketIdx]++;
        }
        for (var bucketIdx = 0; bucketIdx < nBuckets; bucketIdx++) {
            var rangeStartSec = rangeSec * bucketIdx;
            var rangeEndSec = rangeSec * (bucketIdx+1);
            var percentage = 100 * (buckets[bucketIdx] / (double)totalRequests);
            var upperBound = ")";
            if (bucketIdx == nBuckets - 1) {
                // Show an inclusive upper bound. The last bucket includes the maximum time.
                upperBound = "]";
            }
            System.out.printf("[%2.02f-%2.02fs%s : %d (%2.02f%%)\n", rangeStartSec, rangeEndSec, upperBound, buckets[bucketIdx], percentage);
        }

    }
}
