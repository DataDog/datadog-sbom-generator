package dotnet

import "encoding/xml"

// UnmarshalXML implements xml.Unmarshaler to capture line and column positions for each PackageReference.
// This custom unmarshaler is necessary because the standard xml.Unmarshal doesn't provide file position
// information. By manually iterating through XML tokens and calling decoder.InputPos(), we can record
// where each PackageReference appears in the file.
func (itemGroup *ItemGroup) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	// Extract Condition attribute from the ItemGroup element
	for _, attr := range start.Attr {
		if attr.Name.Local == "Condition" {
			conditionValue := attr.Value
			itemGroup.ConditionAttr = &conditionValue

			break
		}
	}

DecodingLoop:
	for {
		lineStart, columnStart := decoder.InputPos()
		token, err := decoder.Token()
		if err != nil {
			return err
		}

		switch elem := token.(type) {
		case xml.StartElement:
			switch elem.Name.Local {
			case "PackageReference":
				packageReference := PackageReference{}
				packageReference.SetLineStart(lineStart)
				packageReference.SetColumnStart(columnStart)

				err := decoder.DecodeElement(&packageReference, &elem)
				if err != nil {
					return err
				}

				lineEnd, columnEnd := decoder.InputPos()
				packageReference.SetLineEnd(lineEnd)
				packageReference.SetColumnEnd(columnEnd)
				itemGroup.PackageReferences = append(itemGroup.PackageReferences, packageReference)

			case "PackageVersion":
				packageVersion := PackageVersion{}
				packageVersion.SetLineStart(lineStart)
				packageVersion.SetColumnStart(columnStart)

				err := decoder.DecodeElement(&packageVersion, &elem)
				if err != nil {
					return err
				}

				lineEnd, columnEnd := decoder.InputPos()
				packageVersion.SetLineEnd(lineEnd)
				packageVersion.SetColumnEnd(columnEnd)
				itemGroup.PackageVersions = append(itemGroup.PackageVersions, packageVersion)
			}

		case xml.EndElement:
			if elem.Name == start.Name {
				break DecodingLoop
			}
		}
	}

	return nil
}
