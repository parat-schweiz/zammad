// Copyright (C) 2012-2023 Zammad Foundation, https://zammad-foundation.org/

import {
  color as inputColorDefinition,
  email as inputEmailDefinition,
  number as inputCNumberDefinition,
  tel as inputTelDefinition,
  text as inputTextDefinition,
  time as inputTimeDefinition,
  textInput,
  url as inputUrlDefinition,
} from '@formkit/inputs'
import initializeFieldDefinition from '#shared/form/core/initializeFieldDefinition.ts'
import addLink from '#shared/form/features/addLink.ts'
import addSubmitEvent from '#shared/form/features/addSubmitEvent.ts'
import formUpdaterTrigger from '#shared/form/features/formUpdaterTrigger.ts'
import type {
  FormFieldsTypeDefinition,
  FormFieldType,
} from '#shared/types/form.ts'

const inputFieldDefinitionList: FormFieldsTypeDefinition = {
  text: inputTextDefinition,
  color: inputColorDefinition,
  email: inputEmailDefinition,
  number: inputCNumberDefinition,
  tel: inputTelDefinition,
  time: inputTimeDefinition,
  url: inputUrlDefinition,
}

const inputFields: FormFieldType[] = []

Object.keys(inputFieldDefinitionList).forEach((inputType) => {
  initializeFieldDefinition(
    inputFieldDefinitionList[inputType],
    { features: [addLink, addSubmitEvent, formUpdaterTrigger('delayed')] },
    { schema: textInput },
  )

  inputFields.push({
    fieldType: inputType,
    definition: inputFieldDefinitionList[inputType],
  })
})

export default inputFields
