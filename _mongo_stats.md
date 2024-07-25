# Find UNSAFEs where the ratios differ

```json
[
  {
    $match:
      /**
       * query: The query in MQL.
       */
      {
        "redirect._classification.classification":
          "UNSAFE",
        "redirect._classification.reason":
          "levenshtein: strongly matching neighbor with different cert"
      }
  },
  {
    $unwind:
      /**
       * path: Path to the array field.
       * includeArrayIndex: Optional name for index.
       * preserveNullAndEmptyArrays: Optional
       *   toggle to unwind null and empty values.
       */
      {
        path: "$redirect",
        includeArrayIndex: "_idx",
        preserveNullAndEmptyArrays: false
      }
  },
  {
    $match:
      /**
       * query: The query in MQL.
       */
      {
        "redirect._classification.classification":
          "UNSAFE",
        "redirect.data.http.result.response.status_code": 200,
        "redirect._classification.reason":
          "levenshtein: strongly matching neighbor with different cert"
      }
  },
  {
    $addFields:
      /**
       * newField: The new field name.
       * expression: The new field expression.
       */
      {
        classification:
          "$redirect._classification"
      }
  },
  {
    $addFields:
      // levenshtein ratio diff
      {
        ratio_safe: {
          $max: [
            "$classification.initial_similarity",
            "$classification.closest_same_cert_similarity"
          ]
        },
        ratio_unsafe:
          "$classification.closest_diff_cert_similarity"
      }
  },
  {
    $addFields: {
      ratio_diff: {
        $subtract: [
          "$ratio_unsafe",
          "$ratio_safe"
        ]
      }
    }
  },
  {
    $sort:
      /**
       * Provide any number of field/order pairs.
       */
      {
        ratio_diff: -1
      }
  },
  {
    $match:
      /**
       * query: The query in MQL.
       */
      {
        "initial.data.http.result.response.content_title":
          {
            $ne: null
          }
      }
  },
  {
    $group:
      /**
       * _id: The id of the group.
       * fieldN: The first field name.
       */
      {
        _id: "$domain_from",
        connections: {
          $push: {
            _id: "$_id",
            from_ip: "$addr_from.ip",
            // initial: "$initial",
            target_ip: "$redirect.ip",
            initial_code:
              "$initial.data.http.result.response.status_code",
            resumed_code:
              "$redirect.data.http.result.response.status_code",
            initial_line:
              "$initial.data.http.result.response.status_line",
            resumed_line:
              "$redirect.data.http.result.response.status_line",
            initial_title:
              "$initial.data.http.result.response.content_title",
            resumed_title:
              "$redirect.data.http.result.response.content_title",
            ratio_safe: "$ratio_safe",
            ratio_unsafe: "$ratio_unsafe",
            ratio_diff: "$ratio_diff",
            classification:
              "$redirect._classification"
          }
        },
        max_ratio_safe: {
          $max: "$ratio_safe"
        },
        min_ratio_safe: {
          $min: "$ratio_safe"
        },
        max_ratio_unsafe: {
          $max: "$ratio_unsafe"
        },
        min_ratio_unsafe: {
          $min: "$ratio_unsafe"
        },
        max_ratio_diff: {
          $max: "$ratio_diff"
        },
        min_ratio_diff: {
          $min: "$ratio_diff"
        }
      }
  },
  {
    $sort:
      /**
       * Provide any number of field/order pairs.
       */
      {
        max_ratio_diff: -1
      }
  }
  // {
  //   $count:
  //     /**
  //      * Provide the field name for the count.
  //      */
  //     "string"
  // }
]
```

# Find UNSAFEs

```json
[
  {
    $match:
      /**
       * query: The query in MQL.
       */
      {
        "redirect._classification.classification":
          "UNSAFE"
      }
  },
  {
    $unwind:
      /**
       * path: Path to the array field.
       * includeArrayIndex: Optional name for index.
       * preserveNullAndEmptyArrays: Optional
       *   toggle to unwind null and empty values.
       */
      {
        path: "$redirect",
        includeArrayIndex: "_idx",
        preserveNullAndEmptyArrays: false
      }
  },
  {
    $match:
      /**
       * query: The query in MQL.
       */
      {
        "redirect._classification.classification":
          "UNSAFE"
      }
  },
  {
    $group:
      /**
       * _id: The id of the group.
       * fieldN: The first field name.
       */
      {
        _id: "$domain_from",
        connections: {
          $push: {
            _id: "$_id",
            from_ip: "$addr_from.ip",
            // initial: "$initial",
            target_ip: "$redirect.ip",
            initial_code:
              "$initial.data.http.result.response.status_code",
            resumed_code:
              "$redirect.data.http.result.response.status_code",
            initial_line:
              "$initial.data.http.result.response.status_line",
            resumed_line:
              "$redirect.data.http.result.response.status_line",
            initial_title:
              "$initial.data.http.result.response.content_title",
            resumed_title:
              "$redirect.data.http.result.response.content_title",
            reason:
              "$redirect._classification.reason",
            classification:
              "$redirect._classification"
          }
        }
      }
  }
  // {
  //   $count:
  //     /**
  //      * Provide the field name for the count.
  //      */
  //     "string"
  // }
]
```


# Find specific redirection results

```json
{
  "redirect":{
    $elemMatch: {
      "_classification.classification": "UNSAFE",
      "_classification.reason": "location",
    }
  }
}
```


# Count Result Status

```json
[
  {
    $group:
      /**
       * _id: The id of the group.
       * fieldN: The first field name.
       */
      {
        _id: "$status",
        count: {
          $count: {},
        },
      },
  },
  {
    $sort:
      /**
       * Provide any number of field/order pairs.
       */
      {
        count: -1,
      },
  },
]
```