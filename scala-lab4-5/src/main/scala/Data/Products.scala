package Data

object Products {
  val price: Map[(String,String),Double] = Map(
    ("croissant", "maison") -> 2.00, // si on ne dit pas la marque
    ("croissant", "cailler") -> 2.00,
    ("biere", "farmer") -> 1.00,
    ("biere", "biere") -> 5.00, // si on ne dit pas la marque
    ("biere", "boxer") -> 1.00,
    ("biere", "wittekop")  -> 2.00,
    ("biere", "punkipa") -> 3.00,
    ("biere", "jackhammer")-> 3.00,
    ("biere", "tenebreuse")  -> 4.00
  )

  val defaultBrand: Map[String,String] = Map (
    ("biere", "boxer") ,
    ("croissant", "maison")
  )
}
